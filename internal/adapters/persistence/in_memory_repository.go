package persistence

import (
	"fmt"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

// InMemoryEventRepository implements the EventRepository port
type InMemoryEventRepository struct {
	store map[string]*models.ProbeEvent
}

// NewInMemoryEventRepository creates a new repository
func NewInMemoryEventRepository() *InMemoryEventRepository {
	return &InMemoryEventRepository{
		store: make(map[string]*models.ProbeEvent),
	}
}

// Save stores a probe event in memory
func (r *InMemoryEventRepository) Save(event *models.ProbeEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}
	r.store[event.ID] = event
	return nil
}

// Get retrieves a probe event by ID
func (r *InMemoryEventRepository) Get(id string) (*models.ProbeEvent, error) {
	event, ok := r.store[id]
	if !ok {
		return nil, fmt.Errorf("event not found")
	}
	return event, nil
}
