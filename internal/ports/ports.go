package ports

import (
	"time"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

// Logger defines the interface for logging implementations.
type Logger interface {
	Info(message string)
	Error(message string)
}

// ChargenEventRepository defines the interface for CHARGEN (RFC 864) probe event persistence.
type ChargenEventRepository interface {
	Save(event *models.ChargenEvent) error
	Get(id string) (*models.ChargenEvent, error)
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

// NTPEventRepository defines the interface for NTP probe event persistence.
type NTPEventRepository interface {
	Save(event *models.NTPEvent) error
	List() ([]*models.NTPEvent, error)
}

type SSDPEventRepository interface {
	Save(event *models.SSDPEvent) error
	List() ([]*models.SSDPEvent, error)
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

// Classifier classifies an incoming probe by source IP and DNS query type string.
// Implementations must be safe for concurrent use.
type Classifier interface {
	Classify(sourceIP string, queryType string) string
	Cleanup(maxAge time.Duration)
}
