package experiment

import (
	"fmt"
	"time"

	"github.com/hacking-lab/ddos-honeypot/internal/domain/models"
	"github.com/hacking-lab/ddos-honeypot/internal/domain/services"
	"github.com/hacking-lab/ddos-honeypot/internal/ports"
)

// AssignVariantUsecase resolves the correct variant for a given (experiment, sourceIP) pair,
// creating a sticky Assignment on first contact so that repeat probes always see the same variant.
type AssignVariantUsecase struct {
	experimentService *services.ExperimentService
	experimentRepo    ports.ExperimentRepository
	assignmentRepo    ports.AssignmentRepository
	logger            ports.Logger
}

// NewAssignVariantUsecase creates a new instance.
func NewAssignVariantUsecase(
	experimentService *services.ExperimentService,
	experimentRepo ports.ExperimentRepository,
	assignmentRepo ports.AssignmentRepository,
	logger ports.Logger,
) *AssignVariantUsecase {
	return &AssignVariantUsecase{
		experimentService: experimentService,
		experimentRepo:    experimentRepo,
		assignmentRepo:    assignmentRepo,
		logger:            logger,
	}
}

// Execute returns the variant for whichever experiment is currently active.
//
// In source mode the assignment is sticky per sourceIP.  In destination mode the variant is
// determined solely by destinationIP (which honeypot IP the probe arrived on).
func (u *AssignVariantUsecase) Execute(sourceIP, destinationIP string) (*models.Variant, error) {
	exp, err := u.experimentRepo.FindActiveExperiment()
	if err != nil {
		return nil, fmt.Errorf("no active experiment: %w", err)
	}

	variants, err := u.experimentRepo.ListVariants(exp.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to list variants for experiment %q: %w", exp.ID, err)
	}

	if exp.AssignmentMode == models.AssignmentByDestination {
		return u.experimentService.AssignVariantByDestination(destinationIP, variants)
	}

	// Source mode: return the existing sticky assignment if present.
	existing, err := u.assignmentRepo.FindBySourceAndExperiment(sourceIP, exp.ID)
	if err == nil && existing != nil {
		variant, err := u.experimentRepo.GetVariant(existing.VariantID)
		if err != nil {
			return nil, fmt.Errorf("assigned variant %q not found: %w", existing.VariantID, err)
		}
		return variant, nil
	}

	// No existing assignment — create one deterministically.
	assigned, err := u.experimentService.AssignVariant(exp.ID, sourceIP, variants)
	if err != nil {
		return nil, fmt.Errorf("variant assignment failed: %w", err)
	}

	a := &models.Assignment{
		SourceIP:     sourceIP,
		ExperimentID: exp.ID,
		VariantID:    assigned.ID,
		AssignedAt:   time.Now(),
	}
	if err := u.assignmentRepo.Save(a); err != nil {
		u.logger.Error(fmt.Sprintf("failed to persist assignment for %s in experiment %q: %v", sourceIP, exp.ID, err))
		return nil, err
	}

	return assigned, nil
}
