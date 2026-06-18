package chargen

import (
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/services"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
)

type HandleChargenRequestUsecase struct {
	chargenService *services.ChargenService
	repository     ports.ChargenEventRepository
	logger         ports.Logger
	rateLimiter    ports.RateLimiter
}

// creates a new instance
func NewHandleChargenRequestUsecase(
	chargenService *services.ChargenService,
	repository ports.ChargenEventRepository,
	logger ports.Logger,
	rateLimiter ports.RateLimiter,
) *HandleChargenRequestUsecase {
	return &HandleChargenRequestUsecase{
		chargenService: chargenService,
		repository:     repository,
		logger:         logger,
		rateLimiter:    rateLimiter,
	}
}

// processes an incoming CHARGEN probe
func (u *HandleChargenRequestUsecase) Execute(sourceIP string, port int, protocol string, payload string) (string, error) {
	u.logger.Info("Processing CHARGEN probe from " + sourceIP)

	event := u.chargenService.ProcessChargen(sourceIP, port, protocol, payload)

	if !u.rateLimiter.Allow(sourceIP, len(event.Response)) {
		u.logger.Info("CHARGEN probe from " + sourceIP + " rate limited")
		return "", nil
	}

	if err := u.repository.Save(event); err != nil {
		u.logger.Error("Failed to save CHARGEN event from " + sourceIP)
		return "", err
	}

	u.logger.Info("CHARGEN probe from " + sourceIP + " processed successfully")
	return event.Response, nil
}
