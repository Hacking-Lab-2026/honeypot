package app

import (
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/handlers"
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/logging"
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/persistence"
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/ratelimit"
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/servers"
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/services"
	"github.com/Hacking-Lab-2026/honeypot/internal/usecases/probe"
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
