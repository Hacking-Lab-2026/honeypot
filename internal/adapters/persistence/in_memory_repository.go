package persistence

import (
	"fmt"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

type InMemoryChargenEventRepository struct {
	store map[string]*models.ChargenEvent
}

func NewInMemoryChargenEventRepository() *InMemoryChargenEventRepository {
	return &InMemoryChargenEventRepository{
		store: make(map[string]*models.ChargenEvent),
	}
}

func (r *InMemoryChargenEventRepository) Save(event *models.ChargenEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}
	r.store[event.ID] = event
	return nil
}

func (r *InMemoryChargenEventRepository) Get(id string) (*models.ChargenEvent, error) {
	event, ok := r.store[id]
	if !ok {
		return nil, fmt.Errorf("event not found")
	}
	return event, nil
}
