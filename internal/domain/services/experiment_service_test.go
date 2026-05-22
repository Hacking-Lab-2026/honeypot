package services_test

import (
	"fmt"
	"testing"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/services"
)

func makeVariants(expID string, weights []float64) []*models.Variant {
	variants := make([]*models.Variant, len(weights))
	for i, w := range weights {
		id := fmt.Sprintf("%c", 'A'+i) // "A", "B", "C", â€¦
		variants[i] = &models.Variant{
			ID:           id,
			ExperimentID: expID,
			Name:         id,
			Weight:       w,
		}
	}
	return variants
}

func TestAssignVariant_Deterministic(t *testing.T) {
	svc := &services.ExperimentService{}
	variants := makeVariants("exp1", []float64{0.5, 0.5})

	v1, err := svc.AssignVariant("exp1", "192.168.1.1", variants)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Calling again with the same inputs must return the same variant.
	for i := 0; i < 10; i++ {
		v2, err := svc.AssignVariant("exp1", "192.168.1.1", variants)
		if err != nil {
			t.Fatalf("unexpected error on call %d: %v", i, err)
		}
		if v2.ID != v1.ID {
			t.Errorf("call %d: got variant %q, want %q (not deterministic)", i, v2.ID, v1.ID)
		}
	}
}

func TestAssignVariant_DifferentSourceIPsMayGetDifferentVariants(t *testing.T) {
	svc := &services.ExperimentService{}
	variants := makeVariants("exp2", []float64{0.5, 0.5})

	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		v, err := svc.AssignVariant("exp2", ip, variants)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		seen[v.ID] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected both variants to be assigned across 200 IPs, got only %v", seen)
	}
}

func TestAssignVariant_WeightedDistribution(t *testing.T) {
	svc := &services.ExperimentService{}
	// 90% / 10% split
	variants := makeVariants("exp3", []float64{0.9, 0.1})

	counts := map[string]int{}
	const total = 1000
	for i := 0; i < total; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
		v, _ := svc.AssignVariant("exp3", ip, variants)
		counts[v.ID]++
	}
	// Variant "A" (weight 0.9) should get roughly 900 / 1000.
	// Generous Â±15% tolerance to account for hash non-uniformity.
	aCount := counts["A"]
	if aCount < 750 || aCount > 1000 {
		t.Errorf("variant A assigned to %d/%d (want ~900, allowed 750â€“1000)", aCount, total)
	}
}

func TestAssignVariant_NoVariants_ReturnsError(t *testing.T) {
	svc := &services.ExperimentService{}
	_, err := svc.AssignVariant("exp4", "1.2.3.4", nil)
	if err == nil {
		t.Error("expected error for empty variants, got nil")
	}
}

func TestValidateExperiment_Valid(t *testing.T) {
	svc := &services.ExperimentService{}
	exp := &models.Experiment{ID: "e1", Name: "Test Experiment"}
	variants := makeVariants("e1", []float64{0.5, 0.5})
	if err := svc.ValidateExperiment(exp, variants); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateExperiment_FewerThanTwoVariants(t *testing.T) {
	svc := &services.ExperimentService{}
	exp := &models.Experiment{ID: "e2", Name: "Solo"}
	variants := makeVariants("e2", []float64{1.0})
	if err := svc.ValidateExperiment(exp, variants); err == nil {
		t.Error("expected error for fewer than 2 variants, got nil")
	}
}

func TestValidateExperiment_WeightsDontSumToOne(t *testing.T) {
	svc := &services.ExperimentService{}
	exp := &models.Experiment{ID: "e3", Name: "Bad Weights"}
	variants := makeVariants("e3", []float64{0.4, 0.4}) // sum = 0.8
	if err := svc.ValidateExperiment(exp, variants); err == nil {
		t.Error("expected error for weights summing to 0.8, got nil")
	}
}

func TestValidateExperiment_NegativeWeight(t *testing.T) {
	svc := &services.ExperimentService{}
	exp := &models.Experiment{ID: "e4", Name: "Negative"}
	variants := makeVariants("e4", []float64{-0.1, 1.1})
	if err := svc.ValidateExperiment(exp, variants); err == nil {
		t.Error("expected error for negative weight, got nil")
	}
}

func TestValidateExperiment_EmptyName(t *testing.T) {
	svc := &services.ExperimentService{}
	exp := &models.Experiment{ID: "e5", Name: ""}
	variants := makeVariants("e5", []float64{0.5, 0.5})
	if err := svc.ValidateExperiment(exp, variants); err == nil {
		t.Error("expected error for empty experiment name, got nil")
	}
}

func TestValidateExperiment_DestinationMode_Valid(t *testing.T) {
	svc := &services.ExperimentService{}
	exp := &models.Experiment{ID: "e6", Name: "Dest", AssignmentMode: models.AssignmentByDestination}
	variants := []*models.Variant{
		{ID: "A", ExperimentID: "e6", Name: "A", AssignedIPs: []string{"10.0.0.1"}},
		{ID: "B", ExperimentID: "e6", Name: "B", AssignedIPs: []string{"10.0.0.2"}},
	}
	if err := svc.ValidateExperiment(exp, variants); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateExperiment_DestinationMode_MissingIPs(t *testing.T) {
	svc := &services.ExperimentService{}
	exp := &models.Experiment{ID: "e7", Name: "Dest", AssignmentMode: models.AssignmentByDestination}
	variants := []*models.Variant{
		{ID: "A", ExperimentID: "e7", Name: "A", AssignedIPs: []string{"10.0.0.1"}},
		{ID: "B", ExperimentID: "e7", Name: "B"}, // no AssignedIPs
	}
	if err := svc.ValidateExperiment(exp, variants); err == nil {
		t.Error("expected error for variant with no assigned IPs, got nil")
	}
}

func TestAssignVariantByDestination_Hit(t *testing.T) {
	svc := &services.ExperimentService{}
	variants := []*models.Variant{
		{ID: "A", Name: "A", AssignedIPs: []string{"10.0.0.1", "10.0.0.2"}},
		{ID: "B", Name: "B", AssignedIPs: []string{"10.0.0.3"}},
	}
	v, err := svc.AssignVariantByDestination("10.0.0.3", variants)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.ID != "B" {
		t.Errorf("got variant %q, want %q", v.ID, "B")
	}
}

func TestAssignVariantByDestination_Miss(t *testing.T) {
	svc := &services.ExperimentService{}
	variants := []*models.Variant{
		{ID: "A", Name: "A", AssignedIPs: []string{"10.0.0.1"}},
	}
	_, err := svc.AssignVariantByDestination("10.0.0.99", variants)
	if err == nil {
		t.Error("expected error for unassigned destination IP, got nil")
	}
}
