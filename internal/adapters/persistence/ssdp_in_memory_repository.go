package persistence

import (
	"fmt"
	"sync"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

// SSDPInMemoryRepository stores SSDP events in memory with mutex protection.
type SSDPInMemoryRepository struct {
	mu     sync.Mutex
	events []*models.SSDPEvent
}

func NewSSDPInMemoryRepository() *SSDPInMemoryRepository {
	return &SSDPInMemoryRepository{}
}

func (r *SSDPInMemoryRepository) Save(event *models.SSDPEvent) error {
	if event == nil {
		return fmt.Errorf("SSDP event cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *SSDPInMemoryRepository) List() ([]*models.SSDPEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := make([]*models.SSDPEvent, len(r.events))
	copy(snap, r.events)
	return snap, nil
}
