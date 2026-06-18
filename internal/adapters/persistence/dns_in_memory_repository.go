package persistence

import (
	"fmt"
	"sync"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

type DNSInMemoryRepository struct {
	mu     sync.Mutex
	events []*models.DNSEvent
}

func NewDNSInMemoryRepository() *DNSInMemoryRepository {
	return &DNSInMemoryRepository{}
}

func (r *DNSInMemoryRepository) Save(event *models.DNSEvent) error {
	if event == nil {
		return fmt.Errorf("DNS event cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *DNSInMemoryRepository) List() ([]*models.DNSEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	snapshot := make([]*models.DNSEvent, len(r.events))
	copy(snapshot, r.events)
	return snapshot, nil
}
