package dns_test

import (
	"encoding/binary"
	"testing"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/services"
	dnsusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/dns"
)

// ---- mock implementations ----

type mockDNSRepo struct {
	saved []*models.DNSEvent
}

func (m *mockDNSRepo) Save(e *models.DNSEvent) error {
	m.saved = append(m.saved, e)
	return nil
}

func (m *mockDNSRepo) List() ([]*models.DNSEvent, error) {
	return m.saved, nil
}

type mockLogger struct{ logs []string }

func (m *mockLogger) Info(msg string)  { m.logs = append(m.logs, "INFO: "+msg) }
func (m *mockLogger) Error(msg string) { m.logs = append(m.logs, "ERROR: "+msg) }

type allowAllLimiter struct{}

func (allowAllLimiter) Allow(_ string, _ int) bool { return true }

type blockAllLimiter struct{}

func (blockAllLimiter) Allow(_ string, _ int) bool { return false }

// ---- tests ----

func buildMinimalQuery() []byte {
	// Reuse helper from parser_test.go (same package)
	return buildRawQuery(0x0001, "example.com", 1)
}

func TestHandleDNSQuery_Execute_ReturnsResponse(t *testing.T) {
	repo := &mockDNSRepo{}
	logger := &mockLogger{}
	uc := dnsusecase.NewHandleDNSQueryUsecase(&services.DNSService{}, repo, logger, allowAllLimiter{})

	config := models.DNSConfig{ResponseMode: models.Minimal, RealisticTTL: true}
	resp, err := uc.Execute("1.2.3.4", 54321, "10.0.0.1", buildMinimalQuery(), config, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("expected non-empty response")
	}
	// Check that one event was persisted
	if len(repo.saved) != 1 {
		t.Fatalf("expected 1 saved event, got %d", len(repo.saved))
	}
	ev := repo.saved[0]
	if ev.SourceIP != "1.2.3.4" {
		t.Errorf("SourceIP = %q, want %q", ev.SourceIP, "1.2.3.4")
	}
	if ev.SourcePort != 54321 {
		t.Errorf("SourcePort = %d, want 54321", ev.SourcePort)
	}
	if ev.QueriedName != "example.com" {
		t.Errorf("QueriedName = %q, want %q", ev.QueriedName, "example.com")
	}
	if ev.QueryType != "A" {
		t.Errorf("QueryType = %q, want %q", ev.QueryType, "A")
	}
	if ev.AmplificationFactor <= 0 {
		t.Errorf("AmplificationFactor = %.2f, want > 0", ev.AmplificationFactor)
	}
}

func TestHandleDNSQuery_Execute_RateLimited_ReturnsNil(t *testing.T) {
	repo := &mockDNSRepo{}
	logger := &mockLogger{}
	uc := dnsusecase.NewHandleDNSQueryUsecase(&services.DNSService{}, repo, logger, blockAllLimiter{})

	resp, err := uc.Execute("9.9.9.9", 1234, "10.0.0.1", buildMinimalQuery(), models.DNSConfig{ResponseMode: models.Minimal}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil {
		t.Errorf("rate-limited probe should return nil response, got %d bytes", len(resp))
	}
	if len(repo.saved) != 0 {
		t.Errorf("rate-limited probe must not be persisted, got %d events", len(repo.saved))
	}
}

func TestHandleDNSQuery_Execute_MalformedPayload_ReturnsError(t *testing.T) {
	repo := &mockDNSRepo{}
	logger := &mockLogger{}
	uc := dnsusecase.NewHandleDNSQueryUsecase(&services.DNSService{}, repo, logger, allowAllLimiter{})

	_, err := uc.Execute("1.2.3.4", 1234, "10.0.0.1", []byte{0x00, 0x01}, models.DNSConfig{ResponseMode: models.Minimal}, "")
	if err == nil {
		t.Error("expected error for malformed payload, got nil")
	}
}

func TestHandleDNSQuery_Execute_AmplifiedConfig(t *testing.T) {
	repo := &mockDNSRepo{}
	logger := &mockLogger{}
	uc := dnsusecase.NewHandleDNSQueryUsecase(&services.DNSService{}, repo, logger, allowAllLimiter{})

	minResp, _ := uc.Execute("1.2.3.4", 1234, "10.0.0.1", buildMinimalQuery(), models.DNSConfig{ResponseMode: models.Minimal}, "")
	// Reset repo
	repo.saved = nil
	ampResp, err := uc.Execute("1.2.3.4", 1234, "10.0.0.1", buildMinimalQuery(), models.DNSConfig{ResponseMode: models.Amplified}, "v2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ampResp) <= len(minResp) {
		t.Errorf("amplified response (%d bytes) should exceed minimal (%d bytes)", len(ampResp), len(minResp))
	}
	// Variant ID should be recorded
	if repo.saved[0].VariantID != "v2" {
		t.Errorf("VariantID = %q, want %q", repo.saved[0].VariantID, "v2")
	}
}

func TestHandleDNSQuery_Execute_ResponseTxIDMatchesQuery(t *testing.T) {
	repo := &mockDNSRepo{}
	logger := &mockLogger{}
	uc := dnsusecase.NewHandleDNSQueryUsecase(&services.DNSService{}, repo, logger, allowAllLimiter{})

	raw := buildRawQuery(0xBEEF, "test.local", 255)
	resp, err := uc.Execute("2.2.2.2", 53, "10.0.0.1", raw, models.DNSConfig{ResponseMode: models.Minimal}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp) < 2 {
		t.Fatal("response too short")
	}
	txID := binary.BigEndian.Uint16(resp[0:2])
	if txID != 0xBEEF {
		t.Errorf("response transaction ID = %04X, want BEEF", txID)
	}
}
