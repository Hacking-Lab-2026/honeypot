package persistence

import (
	"fmt"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

// InMemoryChargenEventRepository implements the ChargenEventRepository port
type InMemoryChargenEventRepository struct {
	store map[string]*models.ChargenEvent
}

// NewInMemoryChargenEventRepository creates a new repository
func NewInMemoryChargenEventRepository() *InMemoryChargenEventRepository {
	return &InMemoryChargenEventRepository{
		store: make(map[string]*models.ChargenEvent),
	}
}

// Save stores a CHARGEN event in memory
func (r *InMemoryChargenEventRepository) Save(event *models.ChargenEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}
	r.store[event.ID] = event
	return nil
}

// Get retrieves a CHARGEN event by ID
func (r *InMemoryChargenEventRepository) Get(id string) (*models.ChargenEvent, error) {
	event, ok := r.store[id]
	if !ok {
		return nil, fmt.Errorf("event not found")
	}
	return event, nil
}
