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
	"github.com/Hacking-Lab-2026/honeypot/internal/usecases/probe"
)

// Config holds all runtime configuration for the application.
type Config struct {
	ProbeAddr       string // UDP probe server address (e.g. "127.0.0.1:53")
	CoordinatorAddr string // HTTP coordinator address (e.g. "0.0.0.0:8080")

	// HoneypotIPs is a comma-separated list of IP addresses to bind DNS servers to.
	// One DNSServer is started per IP.  Example: "10.0.0.1,10.0.0.2,10.0.0.3"
	HoneypotIPs string
	// DNSPort is the port all DNS servers listen on (e.g. "5354" locally, "53" on the VM).
	DNSPort string
	// EventsFile is an optional path to a JSON-lines file for DNS event persistence.
	// When empty, an in-memory repository is used.
	EventsFile string
	// NTPPort is the port NTP servers listen on default 123
	NTPPort string
}

// Application sets up and wires all dependencies.
type Application struct {
	probeServer       *servers.Server
	dnsServers        []*servers.DNSServer
	ntpServers        []*servers.NTPServer
	coordinatorServer *api.CoordinatorServer
	logger            *logging.ConsoleLogger
	classifier        ports.Classifier
	ntpEventRepo      ports.NTPEventRepository
}

// NewApplication creates and initialises the application with all dependencies wired.
// This is the single wiring point â€" no other file may perform dependency injection.
func NewApplication(cfg Config) (*Application, error) {
	logger := &logging.ConsoleLogger{}
	probeRateLimiter := ratelimit.NewIPAggregate(ratelimit.DefaultIPBucketConfig())
	dnsRateLimiter := ratelimit.NewIPAggregate(ratelimit.DefaultIPBucketConfig())
	ntpRateLimiter := ratelimit.NewIPAggregate(ratelimit.DefaultIPBucketConfig())
	classifier := services.NewClassifierService()

	// ── Probe (generic UDP) server ────────────────────────────────────────────────
	probeRepo := persistence.NewInMemoryEventRepository()
	probeService := &services.ProbeService{}
	processProbeUsecase := probe.NewProcessProbeUsecase(probeService, probeRepo, logger, probeRateLimiter)
	probeHandler := handlers.NewProbeHandler(processProbeUsecase)
	probeServer := servers.NewServer(cfg.ProbeAddr, probeHandler, logger)

	// ── DNS event repository (in-memory or file-backed) ───────────────────────────
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

	// ── Experiment / coordinator ──────────────────────────────────────────────────
	experimentRepo := persistence.NewExperimentInMemoryRepository()
	assignmentRepo := persistence.NewAssignmentInMemoryRepository()
	experimentService := &services.ExperimentService{}

	createExperimentUsecase := expusecase.NewCreateExperimentUsecase(experimentService, experimentRepo, logger)
	listExperimentsUsecase := expusecase.NewListExperimentsUsecase(experimentRepo)
	getExperimentUsecase := expusecase.NewGetExperimentUsecase(experimentRepo, assignmentRepo)
	updateStatusUsecase := expusecase.NewUpdateStatusUsecase(experimentRepo, logger)
	assignVariantUsecase := expusecase.NewAssignVariantUsecase(experimentService, experimentRepo, assignmentRepo, logger)

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

	// ── DNS honeypot servers – one per honeypot IP ────────────────────────────────
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

	return &Application{
		probeServer:       probeServer,
		dnsServers:        dnsServers,
		ntpServers:        ntpServers,
		coordinatorServer: coordinatorServer,
		logger:            logger,
		classifier:        classifier,
		ntpEventRepo:      ntpEventRepo,
	}, nil
}

// NTPEventRepository returns the application NTP event repository (useful for tests).
func (a *Application) NTPEventRepository() ports.NTPEventRepository {
	return a.ntpEventRepo
}

// Start launches all servers concurrently and blocks until ctx is cancelled or one server
// returns a fatal error.
func (app *Application) Start(ctx context.Context) error {
	app.logger.Info("Honeypot application starting")

	serverCount := 2 + len(app.dnsServers) + len(app.ntpServers) // probe + coordinator + dns + ntp servers
	errCh := make(chan error, serverCount)

	go func() {
		if err := app.probeServer.Start(ctx); err != nil {
			errCh <- fmt.Errorf("probe server: %w", err)
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

// parseIPs splits a comma-separated IP list, trimming whitespace and skipping empty entries.
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
