package probe

import (
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/services"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
)

// ProcessProbeUsecase handles the core business logic for processing incoming probes
type ProcessProbeUsecase struct {
	probeService *services.ProbeService
	repository   ports.EventRepository
	logger       ports.Logger
	rateLimiter  ports.RateLimiter
}

// NewProcessProbeUsecase creates a new instance
func NewProcessProbeUsecase(
	probeService *services.ProbeService,
	repository ports.EventRepository,
	logger ports.Logger,
	rateLimiter ports.RateLimiter,
) *ProcessProbeUsecase {
	return &ProcessProbeUsecase{
		probeService: probeService,
		repository:   repository,
		logger:       logger,
		rateLimiter:  rateLimiter,
	}
}

// Execute processes an incoming probe
func (u *ProcessProbeUsecase) Execute(sourceIP string, port int, protocol string, payload string) (string, error) {
	u.logger.Info("Processing probe from " + sourceIP)

	// Create probe event through domain service
	event := u.probeService.ProcessProbe(sourceIP, port, protocol, payload)

	// Check rate limiting
	if !u.rateLimiter.Allow(sourceIP, len(event.Response)) {
		u.logger.Info("Probe from " + sourceIP + " rate limited")
		return "", nil
	}

	// Persist the event
	if err := u.repository.Save(event); err != nil {
		u.logger.Error("Failed to save probe event from " + sourceIP)
		return "", err
	}

	u.logger.Info("Probe from " + sourceIP + " processed successfully")
	return event.Response, nil
}
