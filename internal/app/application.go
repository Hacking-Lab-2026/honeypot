package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/hacking-lab/ddos-honeypot/internal/adapters/api"
	"github.com/hacking-lab/ddos-honeypot/internal/adapters/handlers"
	"github.com/hacking-lab/ddos-honeypot/internal/adapters/logging"
	"github.com/hacking-lab/ddos-honeypot/internal/adapters/persistence"
	"github.com/hacking-lab/ddos-honeypot/internal/adapters/ratelimit"
	"github.com/hacking-lab/ddos-honeypot/internal/adapters/servers"
	"github.com/hacking-lab/ddos-honeypot/internal/domain/services"
	dnsusecase "github.com/hacking-lab/ddos-honeypot/internal/usecases/dns"
	expusecase "github.com/hacking-lab/ddos-honeypot/internal/usecases/experiment"
	"github.com/hacking-lab/ddos-honeypot/internal/usecases/probe"
	"github.com/hacking-lab/ddos-honeypot/internal/ports"
)

// Config holds all runtime configuration for the application.
type Config struct {
	ProbeAddr          string // UDP probe server address (e.g. "127.0.0.1:5353")
	CoordinatorAddr    string // HTTP coordinator address (e.g. "0.0.0.0:8080")
	ActiveExperimentID string // ID of the active A/B experiment; "" disables A/B testing

	// HoneypotIPs is a comma-separated list of IP addresses to bind DNS servers to.
	// One DNSServer is started per IP.  Example: "10.0.0.1,10.0.0.2,10.0.0.3"
	HoneypotIPs string
	// DNSPort is the port all DNS servers listen on (e.g. "5354" locally, "53" on the VM).
	DNSPort string
	// EventsFile is an optional path to a JSON-lines file for DNS event persistence.
	// When empty, an in-memory repository is used.
	EventsFile string
}

// Application sets up and wires all dependencies.
type Application struct {
	probeServer       *servers.Server
	dnsServers        []*servers.DNSServer
	coordinatorServer *api.CoordinatorServer
	logger            *logging.ConsoleLogger
}

// NewApplication creates and initialises the application with all dependencies wired.
// This is the single wiring point — no other file may perform dependency injection.
func NewApplication(cfg Config) (*Application, error) {
	logger := &logging.ConsoleLogger{}
	rateLimiter := ratelimit.NewIPAggregate(ratelimit.DefaultIPBucketConfig())

	// ── Probe (generic UDP) server ────────────────────────────────────────────
	probeRepo := persistence.NewInMemoryEventRepository()
	probeService := &services.ProbeService{}
	processProbeUsecase := probe.NewProcessProbeUsecase(probeService, probeRepo, logger, rateLimiter)
	probeHandler := handlers.NewProbeHandler(processProbeUsecase)
	probeServer := servers.NewServer(cfg.ProbeAddr, probeHandler, logger)

	// ── Experiment / coordinator ──────────────────────────────────────────────
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
	)

	// ── DNS event repository (in-memory or file-backed) ───────────────────────
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

	// ── DNS honeypot servers — one per honeypot IP ────────────────────────────
	dnsService := &services.DNSService{}
	handleDNSUsecase := dnsusecase.NewHandleDNSQueryUsecase(dnsService, dnsEventRepo, logger, rateLimiter)
	dnsHandler := handlers.NewDNSHandler(handleDNSUsecase, assignVariantUsecase, cfg.ActiveExperimentID, logger)

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

	return &Application{
		probeServer:       probeServer,
		dnsServers:        dnsServers,
		coordinatorServer: coordinatorServer,
		logger:            logger,
	}, nil
}

// Start launches all servers concurrently and blocks until ctx is cancelled or one server
// returns a fatal error.
func (app *Application) Start(ctx context.Context) error {
	app.logger.Info("Honeypot application starting")

	serverCount := 2 + len(app.dnsServers) // probe + coordinator + dns servers
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
