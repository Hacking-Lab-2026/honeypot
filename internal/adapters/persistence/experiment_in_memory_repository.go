package persistence

import (
	"fmt"
	"sync"

	"github.com/hacking-lab/ddos-honeypot/internal/domain/models"
)

// ExperimentInMemoryRepository implements ports.ExperimentRepository.
// A single RWMutex protects all maps; variants are indexed both by their own ID and by
// experimentID so ListVariants is O(n) in the number of variants for that experiment only.
type ExperimentInMemoryRepository struct {
	mu          sync.RWMutex
	experiments map[string]*models.Experiment
	variants    map[string]*models.Variant            // keyed by variant ID
	byExp       map[string][]string                   // experimentID → []variantID
}

// NewExperimentInMemoryRepository creates a new empty repository.
func NewExperimentInMemoryRepository() *ExperimentInMemoryRepository {
	return &ExperimentInMemoryRepository{
		experiments: make(map[string]*models.Experiment),
		variants:    make(map[string]*models.Variant),
		byExp:       make(map[string][]string),
	}
}

func (r *ExperimentInMemoryRepository) SaveExperiment(exp *models.Experiment) error {
	if exp == nil {
		return fmt.Errorf("experiment cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.experiments[exp.ID] = exp
	return nil
}

func (r *ExperimentInMemoryRepository) GetExperiment(id string) (*models.Experiment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	exp, ok := r.experiments[id]
	if !ok {
		return nil, fmt.Errorf("experiment %q not found", id)
	}
	return exp, nil
}

func (r *ExperimentInMemoryRepository) ListExperiments() ([]*models.Experiment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]*models.Experiment, 0, len(r.experiments))
	for _, e := range r.experiments {
		list = append(list, e)
	}
	return list, nil
}

func (r *ExperimentInMemoryRepository) UpdateExperiment(exp *models.Experiment) error {
	if exp == nil {
		return fmt.Errorf("experiment cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.experiments[exp.ID]; !ok {
		return fmt.Errorf("experiment %q not found", exp.ID)
	}
	r.experiments[exp.ID] = exp
	return nil
}

func (r *ExperimentInMemoryRepository) FindActiveExperiment() (*models.Experiment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, exp := range r.experiments {
		if exp.Status == models.StatusActive {
			return exp, nil
		}
	}
	return nil, fmt.Errorf("no active experiment found")
}

func (r *ExperimentInMemoryRepository) SaveVariant(v *models.Variant) error {
	if v == nil {
		return fmt.Errorf("variant cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.variants[v.ID]; !exists {
		r.byExp[v.ExperimentID] = append(r.byExp[v.ExperimentID], v.ID)
	}
	r.variants[v.ID] = v
	return nil
}

func (r *ExperimentInMemoryRepository) GetVariant(id string) (*models.Variant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.variants[id]
	if !ok {
		return nil, fmt.Errorf("variant %q not found", id)
	}
	return v, nil
}

func (r *ExperimentInMemoryRepository) ListVariants(experimentID string) ([]*models.Variant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := r.byExp[experimentID]
	variants := make([]*models.Variant, 0, len(ids))
	for _, id := range ids {
		if v, ok := r.variants[id]; ok {
			variants = append(variants, v)
		}
	}
	return variants, nil
}

// AssignmentInMemoryRepository implements ports.AssignmentRepository.
// A mutex protects the slice; lookups are O(n) which is acceptable for research scale.
type AssignmentInMemoryRepository struct {
	mu          sync.RWMutex
	assignments []*models.Assignment
}

// NewAssignmentInMemoryRepository creates a new empty repository.
func NewAssignmentInMemoryRepository() *AssignmentInMemoryRepository {
	return &AssignmentInMemoryRepository{}
}

func (r *AssignmentInMemoryRepository) Save(a *models.Assignment) error {
	if a == nil {
		return fmt.Errorf("assignment cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.assignments = append(r.assignments, a)
	return nil
}

func (r *AssignmentInMemoryRepository) FindBySourceAndExperiment(sourceIP, experimentID string) (*models.Assignment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, a := range r.assignments {
		if a.SourceIP == sourceIP && a.ExperimentID == experimentID {
			return a, nil
		}
	}
	return nil, fmt.Errorf("no assignment found for source=%q experiment=%q", sourceIP, experimentID)
}

func (r *AssignmentInMemoryRepository) ListByExperiment(experimentID string) ([]*models.Assignment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.Assignment
	for _, a := range r.assignments {
		if a.ExperimentID == experimentID {
			result = append(result, a)
		}
	}
	return result, nil
}
