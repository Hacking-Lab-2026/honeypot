package services

import (
	"fmt"
	"hash/fnv"
	"math"
	"sort"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

const weightEpsilon = 0.001
type ExperimentService struct{}
func (s *ExperimentService) AssignVariant(experimentID, sourceIP string, variants []*models.Variant) (*models.Variant, error) {
	if len(variants) == 0 {
		return nil, fmt.Errorf("experiment %q has no variants", experimentID)
	}

	h := fnv.New64a()
	h.Write([]byte(experimentID + ":" + sourceIP))
	hash := h.Sum64()
	f := float64(hash) / (float64(^uint64(0)) + 1)
	sorted := make([]*models.Variant, len(variants))
	copy(sorted, variants)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	cumulative := 0.0
	for _, v := range sorted {
		cumulative += v.Weight
		if f < cumulative {
			return v, nil
		}
	}
	return sorted[len(sorted)-1], nil
}

// finds the variant whose AssignedIPs list contains destinationIP
// returns an error if no variant claims that IP
func (s *ExperimentService) AssignVariantByDestination(destinationIP string, variants []*models.Variant) (*models.Variant, error) {
	if len(variants) == 0 {
		return nil, fmt.Errorf("no variants provided")
	}
	for _, v := range variants {
		for _, ip := range v.AssignedIPs {
			if ip == destinationIP {
				return v, nil
			}
		}
	}
	return nil, fmt.Errorf("no variant assigned to destination IP %q", destinationIP)
}

// checks that an experiment configuration is well-formed
// in source mode it verifies weights sum to ~1.0, in destination mode it checks AssignedIPs
func (s *ExperimentService) ValidateExperiment(exp *models.Experiment, variants []*models.Variant) error {
	if exp.Name == "" {
		return fmt.Errorf("experiment name must not be empty")
	}
	if len(variants) < 2 {
		return fmt.Errorf("experiment must have at least 2 variants, got %d", len(variants))
	}

	if exp.AssignmentMode == models.AssignmentByDestination {
		for _, v := range variants {
			if len(v.AssignedIPs) == 0 {
				return fmt.Errorf("variant %q has no assigned IPs (required for destination mode)", v.Name)
			}
		}
	} else {
		// Source mode (default): weights must sum to 1.0
		total := 0.0
		for _, v := range variants {
			if v.Weight < 0 || v.Weight > 1 {
				return fmt.Errorf("variant %q has invalid weight %.4f (must be in [0, 1])", v.Name, v.Weight)
			}
			total += v.Weight
		}
		if math.Abs(total-1.0) > weightEpsilon {
			return fmt.Errorf("variant weights must sum to 1.0, got %.6f", total)
		}
	}

	// Per-variant protocol config validation
	for _, v := range variants {
		if v.NTPConfig.ResponseMode != "" {
			if v.NTPConfig.ResponseMode != "minimal" && v.NTPConfig.ResponseMode != "amplified" {
				return fmt.Errorf("variant %q has invalid NTP response mode %q", v.Name, v.NTPConfig.ResponseMode)
			}
			if v.NTPConfig.ResponseMode == "amplified" && v.NTPConfig.NumPeers <= 0 {
				return fmt.Errorf("variant %q has NTP response mode \"amplified\" but NumPeers must be > 0", v.Name)
			}
		}
	}

	return nil
}
