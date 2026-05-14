package experiment

import (
	"fmt"

	"github.com/hacking-lab/ddos-honeypot/internal/domain/models"
	"github.com/hacking-lab/ddos-honeypot/internal/ports"
)

// ExperimentStats summarises assignment counts for an experiment.
type ExperimentStats struct {
	TotalAssignments int            `json:"total_assignments"`
	PerVariant       map[string]int `json:"per_variant"` // variantID → assignment count
}

// ExperimentDetails bundles an experiment with its variants and runtime stats.
type ExperimentDetails struct {
	Experiment *models.Experiment `json:"experiment"`
	Variants   []*models.Variant  `json:"variants"`
	Stats      ExperimentStats    `json:"stats"`
}

// GetExperimentUsecase fetches an experiment together with its variants and assignment stats.
type GetExperimentUsecase struct {
	experimentRepo ports.ExperimentRepository
	assignmentRepo ports.AssignmentRepository
}

// NewGetExperimentUsecase creates a new instance.
func NewGetExperimentUsecase(
	experimentRepo ports.ExperimentRepository,
	assignmentRepo ports.AssignmentRepository,
) *GetExperimentUsecase {
	return &GetExperimentUsecase{
		experimentRepo: experimentRepo,
		assignmentRepo: assignmentRepo,
	}
}

// Execute retrieves the experiment, its variants, and aggregated assignment statistics.
func (u *GetExperimentUsecase) Execute(experimentID string) (*ExperimentDetails, error) {
	exp, err := u.experimentRepo.GetExperiment(experimentID)
	if err != nil {
		return nil, fmt.Errorf("experiment %q not found: %w", experimentID, err)
	}

	variants, err := u.experimentRepo.ListVariants(experimentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list variants for experiment %q: %w", experimentID, err)
	}

	assignments, err := u.assignmentRepo.ListByExperiment(experimentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list assignments for experiment %q: %w", experimentID, err)
	}

	perVariant := make(map[string]int)
	for _, a := range assignments {
		perVariant[a.VariantID]++
	}

	return &ExperimentDetails{
		Experiment: exp,
		Variants:   variants,
		Stats: ExperimentStats{
			TotalAssignments: len(assignments),
			PerVariant:       perVariant,
		},
	}, nil
}
