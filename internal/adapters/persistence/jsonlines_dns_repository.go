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

type JSONLinesDNSRepository struct {
	mu   sync.Mutex
	file *os.File
}


func NewJSONLinesDNSRepository(path string) (*JSONLinesDNSRepository, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open events file %q: %w", path, err)
	}
	return &JSONLinesDNSRepository{file: f}, nil
}

func (r *JSONLinesDNSRepository) Save(event *models.DNSEvent) error {
	b, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal DNS event: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err = fmt.Fprintf(r.file, "%s\n", b)
	return err
}

func (r *JSONLinesDNSRepository) List() ([]*models.DNSEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, err := r.file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek events file: %w", err)
	}

	var events []*models.DNSEvent
	scanner := bufio.NewScanner(r.file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev models.DNSEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("unmarshal DNS event line: %w", err)
		}
		events = append(events, &ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read events file: %w", err)
	}
	return events, nil
}

func (r *JSONLinesDNSRepository) Close() error {
	return r.file.Close()
}
