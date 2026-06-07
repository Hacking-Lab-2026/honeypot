package persistence

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

// JSONLinesSSDPRepository persists SSDP events to an append-only JSON-lines file.
type JSONLinesSSDPRepository struct {
	mu   sync.Mutex
	file *os.File
}

func NewJSONLinesSSDPRepository(path string) (*JSONLinesSSDPRepository, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open ssdp events file %q: %w", path, err)
	}
	return &JSONLinesSSDPRepository{file: f}, nil
}

func (r *JSONLinesSSDPRepository) Save(event *models.SSDPEvent) error {
	b, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal SSDP event: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err = fmt.Fprintf(r.file, "%s\n", b)
	return err
}

func (r *JSONLinesSSDPRepository) List() ([]*models.SSDPEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek ssdp events file: %w", err)
	}
	var events []*models.SSDPEvent
	scanner := bufio.NewScanner(r.file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev models.SSDPEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("unmarshal SSDP event line: %w", err)
		}
		events = append(events, &ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read ssdp events file: %w", err)
	}
	return events, nil
}

func (r *JSONLinesSSDPRepository) Close() error {
	return r.file.Close()
}
