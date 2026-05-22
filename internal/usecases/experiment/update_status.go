package experiment

import (
	"fmt"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
)

// UpdateStatusUsecase sets an experiment's status to active or stopped.
type UpdateStatusUsecase struct {
	experimentRepo ports.ExperimentRepository
	logger         ports.Logger
}

// NewUpdateStatusUsecase creates a new instance.
func NewUpdateStatusUsecase(experimentRepo ports.ExperimentRepository, logger ports.Logger) *UpdateStatusUsecase {
	return &UpdateStatusUsecase{experimentRepo: experimentRepo, logger: logger}
}

// Execute transitions the experiment to the given status.
func (u *UpdateStatusUsecase) Execute(experimentID string, status models.ExperimentStatus) (*models.Experiment, error) {
	exp, err := u.experimentRepo.GetExperiment(experimentID)
	if err != nil {
		return nil, fmt.Errorf("experiment %q not found: %w", experimentID, err)
	}

	exp.Status = status
	if err := u.experimentRepo.UpdateExperiment(exp); err != nil {
		u.logger.Error(fmt.Sprintf("failed to update status for experiment %q: %v", experimentID, err))
		return nil, err
	}

	u.logger.Info(fmt.Sprintf("experiment %q status set to %q", experimentID, status))
	return exp, nil
}
