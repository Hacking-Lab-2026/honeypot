package app

import (
	"fmt"
	"os"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
	expusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/experiment"
	"gopkg.in/yaml.v3"
)

// experimentSpec is the YAML representation of one experiment to be loaded at startup.
type experimentSpec struct {
	Name           string        `yaml:"name"`
	Description    string        `yaml:"description"`
	AssignmentMode string        `yaml:"assignment_mode"`
	AutoStart      bool          `yaml:"auto_start"`
	Variants       []variantSpec `yaml:"variants"`
}

type variantSpec struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Weight      float64           `yaml:"weight"`
	AssignedIPs []string          `yaml:"assigned_ips"`
	DNSConfig   models.DNSConfig  `yaml:"dns_config"`
	NTPConfig   models.NTPConfig  `yaml:"ntp_config"`
	SSDPConfig  models.SSDPConfig `yaml:"ssdp_config"`
}

type experimentsFile struct {
	Experiments []experimentSpec `yaml:"experiments"`
}

// loadExperimentsFromFile reads the YAML spec and creates+starts experiments via the
// existing usecases. Idempotent: experiments whose name already exists in the repository
// are skipped. Returns the number of experiments newly created.
func loadExperimentsFromFile(
	path string,
	create *expusecase.CreateExperimentUsecase,
	list *expusecase.ListExperimentsUsecase,
	update *expusecase.UpdateStatusUsecase,
	logger ports.Logger,
) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read experiments file %q: %w", path, err)
	}

	var spec experimentsFile
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return 0, fmt.Errorf("parse experiments file %q: %w", path, err)
	}

	existing, err := list.Execute()
	if err != nil {
		return 0, fmt.Errorf("list existing experiments: %w", err)
	}
	existingByName := make(map[string]*models.Experiment, len(existing))
	for _, e := range existing {
		existingByName[e.Name] = e
	}

	created := 0
	for _, s := range spec.Experiments {
		if _, ok := existingByName[s.Name]; ok {
			logger.Info(fmt.Sprintf("experiment %q already exists, skipping", s.Name))
			continue
		}

		input := expusecase.CreateExperimentInput{
			Name:           s.Name,
			Description:    s.Description,
			AssignmentMode: models.AssignmentMode(s.AssignmentMode),
			Variants:       make([]expusecase.CreateVariantInput, len(s.Variants)),
		}
		for i, v := range s.Variants {
			input.Variants[i] = expusecase.CreateVariantInput{
				Name:        v.Name,
				Description: v.Description,
				Weight:      v.Weight,
				AssignedIPs: v.AssignedIPs,
				DNSConfig:   v.DNSConfig,
				NTPConfig:   v.NTPConfig,
				SSDPConfig:  v.SSDPConfig,
			}
		}

		exp, err := create.Execute(input)
		if err != nil {
			return created, fmt.Errorf("create experiment %q: %w", s.Name, err)
		}

		if s.AutoStart {
			if _, err := update.Execute(exp.ID, models.StatusActive); err != nil {
				return created, fmt.Errorf("start experiment %q: %w", s.Name, err)
			}
			logger.Info(fmt.Sprintf("experiment %q created and started (id=%s)", exp.Name, exp.ID))
		} else {
			logger.Info(fmt.Sprintf("experiment %q created in stopped state (id=%s)", exp.Name, exp.ID))
		}

		created++
	}

	return created, nil
}
