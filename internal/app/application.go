package app

import (
	"github.com/hacking-lab/ddos-honeypot/internal/adapters/handlers"
	"github.com/hacking-lab/ddos-honeypot/internal/adapters/logging"
	"github.com/hacking-lab/ddos-honeypot/internal/adapters/persistence"
	"github.com/hacking-lab/ddos-honeypot/internal/adapters/ratelimit"
	"github.com/hacking-lab/ddos-honeypot/internal/adapters/servers"
	"github.com/hacking-lab/ddos-honeypot/internal/domain/services"
	"github.com/hacking-lab/ddos-honeypot/internal/usecases/probe"
)

// Application sets up and wires all dependencies
type Application struct {
	Server *servers.Server
	Logger *logging.ConsoleLogger
}

// NewApplication creates and initializes the application
func NewApplication(listenAddr string) *Application {
	// Initialize adapters
	logger := &logging.ConsoleLogger{}
	repository := persistence.NewInMemoryEventRepository()
	rateLimiter := &ratelimit.NoOpRateLimiter{}

	// Initialize domain services
	probeService := &services.ProbeService{}

	// Initialize usecases
	processProbeUsecase := probe.NewProcessProbeUsecase(
		probeService,
		repository,
		logger,
		rateLimiter,
	)

	// Initialize handlers
	probeHandler := handlers.NewProbeHandler(processProbeUsecase)

	// Initialize endpoint (UDP server)
	server := servers.NewServer(listenAddr, probeHandler, logger)

	return &Application{
		Server: server,
		Logger: logger,
	}
}

// Start begins running the honeypot
func (app *Application) Start() error {
	app.Logger.Info("Honeypot application initialized")
	return app.Server.Start()
}
