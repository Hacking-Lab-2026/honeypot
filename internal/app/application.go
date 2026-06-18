package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/api"
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/handlers"
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/logging"
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/persistence"
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/ratelimit"
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/servers"
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/services"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
	dnsusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/dns"
	expusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/experiment"
	ntpusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/ntp"
	chargenUsecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/chargen"
	ssdpusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/ssdp"
)

type Config struct {
	ChargenAddr     string // CHARGEN server address (e.g. "0.0.0.0:19")
	CoordinatorAddr string // HTTP coordinator address (e.g. "0.0.0.0:8080")

	// One DNSServer is started per IP.  Example: "10.0.0.1,10.0.0.2,10.0.0.3"
	HoneypotIPs string
	// DNSPort is the port all DNS servers listen on (e.g. "5354" locally, "53" on the VM).
	DNSPort string

	EventsFile string

	// NTPPort is the port NTP servers listen on default 123
	NTPPort string
	// SSDP, def 1900
	SSDPPort string
	
	ExperimentsFile string
}

// Application sets up and wires all dependencies
type Application struct {
	chargenServer     *servers.ChargenServer
	dnsServers        []*servers.DNSServer
	ntpServers        []*servers.NTPServer
	ssdpServers       []*servers.SSDPServer
	coordinatorServer *api.CoordinatorServer
	logger            *logging.ConsoleLogger
	classifier        ports.Classifier
	ntpEventRepo      ports.NTPEventRepository
}


func NewApplication(cfg Config) (*Application, error) {
	logger := &logging.ConsoleLogger{}
	chargenRateLimiter := ratelimit.NewIPAggregate(ratelimit.DefaultIPBucketConfig())
	dnsRateLimiter := ratelimit.NewIPAggregate(ratelimit.DefaultIPBucketConfig())
	ntpRateLimiter := ratelimit.NewIPAggregate(ratelimit.DefaultIPBucketConfig())
	ssdpRateLimiter := ratelimit.NewIPAggregate(ratelimit.DefaultIPBucketConfig())
	classifier := services.NewClassifierService()

	// Chargen
	chargenRepo := persistence.NewInMemoryChargenEventRepository()
	chargenService := &services.ChargenService{}
	handleChargenUsecase := chargenUsecase.NewHandleChargenRequestUsecase(chargenService, chargenRepo, logger, chargenRateLimiter)
	chargenHandler := handlers.NewChargenHandler(handleChargenUsecase)
	chargenServer := servers.NewChargenServer(cfg.ChargenAddr, chargenHandler, logger)

	// Dns
	var dnsEventRepo ports.DNSEventRepository
	if cfg.EventsFile != "" {
		repo, err := persistence.NewJSONLinesDNSRepository(cfg.EventsFile)
		if err != nil {
			return nil, fmt.Errorf("open events file: %w", err)
		}
		dnsEventRepo = repo
		logger.Info("DNS events will be persisted to " + cfg.EventsFile)
	} else {
		dnsEventRepo = persistence.NewDNSInMemoryRepository()
	}

	// NTP repo
	var ntpEventRepo ports.NTPEventRepository
	if cfg.EventsFile != "" {
		repo, err := persistence.NewJSONLinesNTPRepository(cfg.EventsFile)
		if err != nil {
			return nil, fmt.Errorf("open ntp events file: %w", err)
		}
		ntpEventRepo = repo
		logger.Info("NTP events will be persisted to " + cfg.EventsFile)
	} else {
		ntpEventRepo = persistence.NewNTPInMemoryRepository()
	}

	var ssdpEventRepo ports.SSDPEventRepository
	if cfg.EventsFile != "" {
		repo, err := persistence.NewJSONLinesSSDPRepository(cfg.EventsFile)
		if err != nil {
			return nil, fmt.Errorf("open ssdp events file: %w", err)
		}
		ssdpEventRepo = repo
		logger.Info("SSDP events will be persisted to " + cfg.EventsFile)
	} else {
		ssdpEventRepo = persistence.NewSSDPInMemoryRepository()
	}

	// Experiments
	experimentRepo := persistence.NewExperimentInMemoryRepository()
	assignmentRepo := persistence.NewAssignmentInMemoryRepository()
	experimentService := &services.ExperimentService{}

	createExperimentUsecase := expusecase.NewCreateExperimentUsecase(experimentService, experimentRepo, logger)
	listExperimentsUsecase := expusecase.NewListExperimentsUsecase(experimentRepo)
	getExperimentUsecase := expusecase.NewGetExperimentUsecase(experimentRepo, assignmentRepo)
	updateStatusUsecase := expusecase.NewUpdateStatusUsecase(experimentRepo, logger)
	assignVariantUsecase := expusecase.NewAssignVariantUsecase(experimentService, experimentRepo, assignmentRepo, logger)

	// Load Experiments
	if cfg.ExperimentsFile != "" {
		n, err := loadExperimentsFromFile(
			cfg.ExperimentsFile,
			createExperimentUsecase,
			listExperimentsUsecase,
			updateStatusUsecase,
			logger,
		)
		if err != nil {
			return nil, fmt.Errorf("load experiments: %w", err)
		}
		logger.Info(fmt.Sprintf("loaded experiments from %s: %d new", cfg.ExperimentsFile, n))
	}

	coordinatorServer := api.NewCoordinatorServer(
		cfg.CoordinatorAddr,
		createExperimentUsecase,
		listExperimentsUsecase,
		getExperimentUsecase,
		updateStatusUsecase,
		logger,
		dnsEventRepo,
		ntpEventRepo,
	)

	// Dns honey pot
	dnsService := &services.DNSService{}
	handleDNSUsecase := dnsusecase.NewHandleDNSQueryUsecase(dnsService, dnsEventRepo, logger, dnsRateLimiter, classifier)
	dnsHandler := handlers.NewDNSHandler(handleDNSUsecase, assignVariantUsecase, logger)

	ips := parseIPs(cfg.HoneypotIPs)
	if len(ips) == 0 {
		ips = []string{"127.0.0.1"}
	}
	port := cfg.DNSPort
	if port == "" {
		port = "5354"
	}

	dnsServers := make([]*servers.DNSServer, len(ips))
	for i, ip := range ips {
		addr := ip + ":" + port
		dnsServers[i] = servers.NewDNSServer(addr, ip, dnsHandler, logger)
	}

	// ntp honeypot server
	ntpService := &services.NTPService{}
	handleNTPUsecase := ntpusecase.NewHandleNTPRequestUsecase(ntpService, ntpEventRepo, logger, ntpRateLimiter, classifier)
	ntpHandler := handlers.NewNTPHandler(handleNTPUsecase, assignVariantUsecase, logger)

	ntpPort := cfg.NTPPort
	if ntpPort == "" {
		ntpPort = "123"
	}

	ntpServers := make([]*servers.NTPServer, len(ips))
	for i, ip := range ips {
		addr := ip + ":" + ntpPort
		ntpServers[i] = servers.NewNTPServer(addr, ip, ntpHandler, logger)
	}
	// SSDP honeypot 
	ssdpService := &services.SSDPService{}
	handleSSDPUsecase := ssdpusecase.NewHandleSSDPRequestUsecase(ssdpService, ssdpEventRepo, logger, ssdpRateLimiter, classifier)
	ssdpHandler := handlers.NewSSDPHandler(handleSSDPUsecase, assignVariantUsecase, logger)

	ssdpPort := cfg.SSDPPort
	if ssdpPort == "" {
		ssdpPort = "1900"
	}

	ssdpServers := make([]*servers.SSDPServer, len(ips))
	for i, ip := range ips {
		addr := ip + ":" + ssdpPort
		ssdpServers[i] = servers.NewSSDPServer(addr, ip, ssdpHandler, logger)
	}

	return &Application{
		chargenServer:     chargenServer,
		dnsServers:        dnsServers,
		ntpServers:        ntpServers,
		ssdpServers:       ssdpServers,
		coordinatorServer: coordinatorServer,
		logger:            logger,
		classifier:        classifier,
		ntpEventRepo:      ntpEventRepo,
	}, nil
}

// NTPEventRepository returns the application NTP event repository
func (a *Application) NTPEventRepository() ports.NTPEventRepository {
	return a.ntpEventRepo
}

// Start launches all servers
func (app *Application) Start(ctx context.Context) error {
	app.logger.Info("Honeypot application starting")

	serverCount := 2 + len(app.dnsServers) + len(app.ntpServers) + len(app.ssdpServers) // chargen + coordinator + dns + ntp + ssdp servers
	errCh := make(chan error, serverCount)

	go func() {
		if err := app.chargenServer.Start(ctx); err != nil {
			errCh <- fmt.Errorf("chargen server: %w", err)
		}
	}()

	go func() {
		if err := app.coordinatorServer.Start(ctx); err != nil {
			errCh <- fmt.Errorf("coordinator server: %w", err)
		}
	}()

	for _, ds := range app.dnsServers {
		ds := ds // capture loop variable
		go func() {
			if err := ds.Start(ctx); err != nil {
				errCh <- fmt.Errorf("dns server %s: %w", ds.Addr(), err)
			}
		}()
	}

	for _, ns := range app.ntpServers {
		ns := ns
		go func() {
			if err := ns.Start(ctx); err != nil {
				errCh <- fmt.Errorf("ntp server %s: %w", ns.Addr(), err)
			}
		}()
	}

	for _, ss := range app.ssdpServers {
		ss := ss
		go func() {
			if err := ss.Start(ctx); err != nil {
				errCh <- fmt.Errorf("ssdp server %s: %w", ss.Addr(), err)
			}
		}()
	}
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				app.classifier.Cleanup(10 * time.Minute)
			case <-ctx.Done():
				return
			}
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return nil
	}
}

// splits a comma-separated IP list, trimming whitespace and skipping empty entries
func parseIPs(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if ip := strings.TrimSpace(p); ip != "" {
			result = append(result, ip)
		}
	}
	return result
}
