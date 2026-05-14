package experiment_test

import (
	"fmt"
	"testing"

	"github.com/hacking-lab/ddos-honeypot/internal/domain/models"
	"github.com/hacking-lab/ddos-honeypot/internal/domain/services"
	expusecase "github.com/hacking-lab/ddos-honeypot/internal/usecases/experiment"
)

// ---- mocks ----

type mockExperimentRepo struct {
	experiments map[string]*models.Experiment
	variants    map[string]*models.Variant
	byExp       map[string][]string
}

func newMockExperimentRepo() *mockExperimentRepo {
	return &mockExperimentRepo{
		experiments: make(map[string]*models.Experiment),
		variants:    make(map[string]*models.Variant),
		byExp:       make(map[string][]string),
	}
}

func (r *mockExperimentRepo) SaveExperiment(exp *models.Experiment) error {
	r.experiments[exp.ID] = exp
	return nil
}

func (r *mockExperimentRepo) GetExperiment(id string) (*models.Experiment, error) {
	if e, ok := r.experiments[id]; ok {
		return e, nil
	}
	return nil, fmt.Errorf("not found")
}

func (r *mockExperimentRepo) ListExperiments() ([]*models.Experiment, error) {
	list := make([]*models.Experiment, 0, len(r.experiments))
	for _, e := range r.experiments {
		list = append(list, e)
	}
	return list, nil
}

func (r *mockExperimentRepo) UpdateExperiment(exp *models.Experiment) error {
	r.experiments[exp.ID] = exp
	return nil
}

func (r *mockExperimentRepo) SaveVariant(v *models.Variant) error {
	if _, exists := r.variants[v.ID]; !exists {
		r.byExp[v.ExperimentID] = append(r.byExp[v.ExperimentID], v.ID)
	}
	r.variants[v.ID] = v
	return nil
}

func (r *mockExperimentRepo) GetVariant(id string) (*models.Variant, error) {
	if v, ok := r.variants[id]; ok {
		return v, nil
	}
	return nil, fmt.Errorf("not found")
}

func (r *mockExperimentRepo) ListVariants(experimentID string) ([]*models.Variant, error) {
	var result []*models.Variant
	for _, id := range r.byExp[experimentID] {
		if v, ok := r.variants[id]; ok {
			result = append(result, v)
		}
	}
	return result, nil
}

type mockExpLogger struct{}

func (m *mockExpLogger) Info(_ string)  {}
func (m *mockExpLogger) Error(_ string) {}

// ---- tests ----

func TestCreateExperiment_Valid(t *testing.T) {
	repo := newMockExperimentRepo()
	uc := expusecase.NewCreateExperimentUsecase(&services.ExperimentService{}, repo, &mockExpLogger{})

	exp, err := uc.Execute(expusecase.CreateExperimentInput{
		Name:        "Test Experiment",
		Description: "A/B test",
		Variants: []expusecase.CreateVariantInput{
			{Name: "Control", Weight: 0.5, DNSConfig: models.DNSConfig{ResponseMode: models.Minimal}},
			{Name: "Treatment", Weight: 0.5, DNSConfig: models.DNSConfig{ResponseMode: models.Amplified}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp.ID == "" {
		t.Error("experiment ID must not be empty")
	}
	if exp.Name != "Test Experiment" {
		t.Errorf("Name = %q, want %q", exp.Name, "Test Experiment")
	}
	if exp.Status != models.StatusStopped {
		t.Errorf("Status = %q, want %q", exp.Status, models.StatusStopped)
	}

	// Both variants must be persisted.
	variants, err := repo.ListVariants(exp.ID)
	if err != nil || len(variants) != 2 {
		t.Errorf("expected 2 variants, got %d (err=%v)", len(variants), err)
	}
}

func TestCreateExperiment_WeightsDontSumToOne_ReturnsError(t *testing.T) {
	repo := newMockExperimentRepo()
	uc := expusecase.NewCreateExperimentUsecase(&services.ExperimentService{}, repo, &mockExpLogger{})

	_, err := uc.Execute(expusecase.CreateExperimentInput{
		Name: "Bad Weights",
		Variants: []expusecase.CreateVariantInput{
			{Name: "A", Weight: 0.3},
			{Name: "B", Weight: 0.3},
		},
	})
	if err == nil {
		t.Error("expected error for weights summing to 0.6, got nil")
	}
}

func TestCreateExperiment_FewerThanTwoVariants_ReturnsError(t *testing.T) {
	repo := newMockExperimentRepo()
	uc := expusecase.NewCreateExperimentUsecase(&services.ExperimentService{}, repo, &mockExpLogger{})

	_, err := uc.Execute(expusecase.CreateExperimentInput{
		Name:     "Solo",
		Variants: []expusecase.CreateVariantInput{{Name: "Only", Weight: 1.0}},
	})
	if err == nil {
		t.Error("expected error for single variant, got nil")
	}
}

func TestCreateExperiment_EmptyName_ReturnsError(t *testing.T) {
	repo := newMockExperimentRepo()
	uc := expusecase.NewCreateExperimentUsecase(&services.ExperimentService{}, repo, &mockExpLogger{})

	_, err := uc.Execute(expusecase.CreateExperimentInput{
		Name: "",
		Variants: []expusecase.CreateVariantInput{
			{Name: "A", Weight: 0.5},
			{Name: "B", Weight: 0.5},
		},
	})
	if err == nil {
		t.Error("expected error for empty experiment name, got nil")
	}
}

func TestCreateExperiment_DestinationMode_Valid(t *testing.T) {
	repo := newMockExperimentRepo()
	uc := expusecase.NewCreateExperimentUsecase(&services.ExperimentService{}, repo, &mockExpLogger{})

	exp, err := uc.Execute(expusecase.CreateExperimentInput{
		Name:           "Multi-IP Test",
		AssignmentMode: models.AssignmentByDestination,
		Variants: []expusecase.CreateVariantInput{
			{Name: "Minimal", AssignedIPs: []string{"10.0.0.1", "10.0.0.2"}, DNSConfig: models.DNSConfig{ResponseMode: models.Minimal}},
			{Name: "Amplified", AssignedIPs: []string{"10.0.0.3", "10.0.0.4"}, DNSConfig: models.DNSConfig{ResponseMode: models.Amplified}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp.AssignmentMode != models.AssignmentByDestination {
		t.Errorf("AssignmentMode = %q, want %q", exp.AssignmentMode, models.AssignmentByDestination)
	}

	variants, _ := repo.ListVariants(exp.ID)
	if len(variants) != 2 {
		t.Fatalf("expected 2 variants, got %d", len(variants))
	}
	for _, v := range variants {
		if len(v.AssignedIPs) == 0 {
			t.Errorf("variant %q has no AssignedIPs", v.Name)
		}
	}
}

func TestCreateExperiment_DefaultsToSourceMode(t *testing.T) {
	repo := newMockExperimentRepo()
	uc := expusecase.NewCreateExperimentUsecase(&services.ExperimentService{}, repo, &mockExpLogger{})

	exp, err := uc.Execute(expusecase.CreateExperimentInput{
		Name: "Default Mode",
		Variants: []expusecase.CreateVariantInput{
			{Name: "A", Weight: 0.5, DNSConfig: models.DNSConfig{ResponseMode: models.Minimal}},
			{Name: "B", Weight: 0.5, DNSConfig: models.DNSConfig{ResponseMode: models.Amplified}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp.AssignmentMode != models.AssignmentBySource {
		t.Errorf("AssignmentMode = %q, want %q", exp.AssignmentMode, models.AssignmentBySource)
	}
}
