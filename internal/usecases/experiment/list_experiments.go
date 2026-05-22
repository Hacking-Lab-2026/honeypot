package experiment

import (
	"fmt"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
)

// ListExperimentsUsecase retrieves all experiments from the repository.
type ListExperimentsUsecase struct {
	experimentRepo ports.ExperimentRepository
}

// NewListExperimentsUsecase creates a new instance.
func NewListExperimentsUsecase(experimentRepo ports.ExperimentRepository) *ListExperimentsUsecase {
	return &ListExperimentsUsecase{experimentRepo: experimentRepo}
}

// Execute returns all experiments, or an error if the repository call fails.
func (u *ListExperimentsUsecase) Execute() ([]*models.Experiment, error) {
	exps, err := u.experimentRepo.ListExperiments()
	if err != nil {
		return nil, fmt.Errorf("failed to list experiments: %w", err)
	}
	return exps, nil
}
