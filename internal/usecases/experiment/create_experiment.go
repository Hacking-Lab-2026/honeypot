package experiment

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/hacking-lab/ddos-honeypot/internal/domain/models"
	"github.com/hacking-lab/ddos-honeypot/internal/domain/services"
	"github.com/hacking-lab/ddos-honeypot/internal/ports"
)

// CreateVariantInput holds the caller-supplied fields for a single variant.
type CreateVariantInput struct {
	Name        string
	Description string
	Weight      float64
	AssignedIPs []string // destination-mode only
	DNSConfig   models.DNSConfig
}

// CreateExperimentInput holds the caller-supplied fields for a new experiment.
type CreateExperimentInput struct {
	Name           string
	Description    string
	AssignmentMode models.AssignmentMode // defaults to AssignmentBySource when empty
	Variants       []CreateVariantInput
}

// CreateExperimentUsecase validates and persists a new experiment with its variants.
type CreateExperimentUsecase struct {
	experimentService *services.ExperimentService
	experimentRepo    ports.ExperimentRepository
	logger            ports.Logger
}

// NewCreateExperimentUsecase creates a new instance.
func NewCreateExperimentUsecase(
	experimentService *services.ExperimentService,
	experimentRepo ports.ExperimentRepository,
	logger ports.Logger,
) *CreateExperimentUsecase {
	return &CreateExperimentUsecase{
		experimentService: experimentService,
		experimentRepo:    experimentRepo,
		logger:            logger,
	}
}

// Execute validates the input, assigns IDs, and persists the experiment.
func (u *CreateExperimentUsecase) Execute(input CreateExperimentInput) (*models.Experiment, error) {
	mode := input.AssignmentMode
	if mode == "" {
		mode = models.AssignmentBySource
	}

	expID := newUUID()
	exp := &models.Experiment{
		ID:             expID,
		Name:           input.Name,
		Description:    input.Description,
		Status:         models.StatusStopped,
		AssignmentMode: mode,
		CreatedAt:      time.Now(),
	}

	variants := make([]*models.Variant, len(input.Variants))
	for i, vi := range input.Variants {
		variants[i] = &models.Variant{
			ID:           newUUID(),
			ExperimentID: expID,
			Name:         vi.Name,
			Description:  vi.Description,
			Weight:       vi.Weight,
			AssignedIPs:  vi.AssignedIPs,
			DNSConfig:    vi.DNSConfig,
		}
	}

	if err := u.experimentService.ValidateExperiment(exp, variants); err != nil {
		return nil, fmt.Errorf("invalid experiment: %w", err)
	}

	if err := u.experimentRepo.SaveExperiment(exp); err != nil {
		u.logger.Error(fmt.Sprintf("failed to save experiment %q: %v", exp.ID, err))
		return nil, err
	}
	for _, v := range variants {
		if err := u.experimentRepo.SaveVariant(v); err != nil {
			u.logger.Error(fmt.Sprintf("failed to save variant %q: %v", v.ID, err))
			return nil, err
		}
	}

	u.logger.Info(fmt.Sprintf("created experiment %q (%s) with %d variants", exp.Name, exp.ID, len(variants)))
	return exp, nil
}

// newUUID generates a random UUID v4 string using crypto/rand.
func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}
