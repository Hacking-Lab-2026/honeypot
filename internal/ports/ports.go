package ports

import "github.com/Hacking-Lab-2026/honeypot/internal/domain/models"

// Logger defines the interface for logging implementations
type Logger interface {
	Info(message string)
	Error(message string)
}

// EventRepository defines the interface for probe event persistence
type EventRepository interface {
	Save(event *models.ProbeEvent) error
	Get(id string) (*models.ProbeEvent, error)
}

// RateLimiter defines the interface for rate limiting strategies
type RateLimiter interface {
	Allow(sourceIP string, responseBytes int) bool
}
