package experiment

import (
	"fmt"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
)

type ListExperimentsUsecase struct {
	experimentRepo ports.ExperimentRepository
}

func NewListExperimentsUsecase(experimentRepo ports.ExperimentRepository) *ListExperimentsUsecase {
	return &ListExperimentsUsecase{experimentRepo: experimentRepo}
}

func (u *ListExperimentsUsecase) Execute() ([]*models.Experiment, error) {
	exps, err := u.experimentRepo.ListExperiments()
	if err != nil {
		return nil, fmt.Errorf("failed to list experiments: %w", err)
	}
	return exps, nil
}
