package ports

import "github.com/Hacking-Lab-2026/honeypot/internal/domain/models"

// Logger defines the interface for logging implementations.
type Logger interface {
	Info(message string)
	Error(message string)
}

// EventRepository defines the interface for probe event persistence.
type EventRepository interface {
	Save(event *models.ProbeEvent) error
	Get(id string) (*models.ProbeEvent, error)
}

// RateLimiter defines the interface for rate-limiting strategies.
// It operates per source IP and can be shared across services.
type RateLimiter interface {
	Allow(sourceIP string, responseBytes int) bool
}

// DNSEventRepository defines the interface for DNS probe event persistence.
type DNSEventRepository interface {
	Save(event *models.DNSEvent) error
	List() ([]*models.DNSEvent, error)
}

// ExperimentRepository defines CRUD operations for experiments and their variants.
type ExperimentRepository interface {
	SaveExperiment(exp *models.Experiment) error
	GetExperiment(id string) (*models.Experiment, error)
	ListExperiments() ([]*models.Experiment, error)
	UpdateExperiment(exp *models.Experiment) error
	FindActiveExperiment() (*models.Experiment, error)
	SaveVariant(v *models.Variant) error
	GetVariant(id string) (*models.Variant, error)
	ListVariants(experimentID string) ([]*models.Variant, error)
}

// AssignmentRepository defines read/write access to sticky variant assignments.
type AssignmentRepository interface {
	Save(a *models.Assignment) error
	FindBySourceAndExperiment(sourceIP, experimentID string) (*models.Assignment, error)
	ListByExperiment(experimentID string) ([]*models.Assignment, error)
}
