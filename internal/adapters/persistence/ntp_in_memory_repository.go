package persistence

import (
	"fmt"
	"sync"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

// NTPInMemoryRepository stores NTP events in memory with mutex protection.
type NTPInMemoryRepository struct {
	mu     sync.Mutex
	events []*models.NTPEvent
}

func NewNTPInMemoryRepository() *NTPInMemoryRepository {
	return &NTPInMemoryRepository{}
}

func (r *NTPInMemoryRepository) Save(event *models.NTPEvent) error {
	if event == nil {
		return fmt.Errorf("NTP event cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *NTPInMemoryRepository) List() ([]*models.NTPEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := make([]*models.NTPEvent, len(r.events))
	copy(snap, r.events)
	return snap, nil
}
