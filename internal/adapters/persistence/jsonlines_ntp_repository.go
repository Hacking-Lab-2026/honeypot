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

// JSONLinesNTPRepository persists NTP events to an append-only JSON-lines file.
type JSONLinesNTPRepository struct {
	mu   sync.Mutex
	file *os.File
}

func NewJSONLinesNTPRepository(path string) (*JSONLinesNTPRepository, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open ntp events file %q: %w", path, err)
	}
	return &JSONLinesNTPRepository{file: f}, nil
}

func (r *JSONLinesNTPRepository) Save(event *models.NTPEvent) error {
	b, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal NTP event: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err = fmt.Fprintf(r.file, "%s\n", b)
	return err
}

func (r *JSONLinesNTPRepository) List() ([]*models.NTPEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek ntp events file: %w", err)
	}
	var events []*models.NTPEvent
	scanner := bufio.NewScanner(r.file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev models.NTPEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("unmarshal NTP event line: %w", err)
		}
		events = append(events, &ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read ntp events file: %w", err)
	}
	return events, nil
}

func (r *JSONLinesNTPRepository) Close() error {
	return r.file.Close()
}
