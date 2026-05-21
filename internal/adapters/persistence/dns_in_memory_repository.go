package persistence

import (
	"fmt"
	"sync"

	"github.com/hacking-lab/ddos-honeypot/internal/domain/models"
)

// DNSInMemoryRepository implements ports.DNSEventRepository using an in-memory slice.
// A mutex protects all reads and writes because the DNS server spawns one goroutine per packet.
type DNSInMemoryRepository struct {
	mu     sync.Mutex
	events []*models.DNSEvent
}

// NewDNSInMemoryRepository creates a new empty repository.
func NewDNSInMemoryRepository() *DNSInMemoryRepository {
	return &DNSInMemoryRepository{}
}

// Save appends a DNS event to the in-memory store.
func (r *DNSInMemoryRepository) Save(event *models.DNSEvent) error {
	if event == nil {
		return fmt.Errorf("DNS event cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

// List returns a snapshot of all stored DNS events.
func (r *DNSInMemoryRepository) List() ([]*models.DNSEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	snapshot := make([]*models.DNSEvent, len(r.events))
	copy(snapshot, r.events)
	return snapshot, nil
}
