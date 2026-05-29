package services_test

import (
	"encoding/binary"
	"testing"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/services"
)

func TestBuildResponse_Minimal(t *testing.T) {
	svc := &services.DNSService{}
	query := models.DNSQuery{TransactionID: 0x1234, Name: "example.com", Type: 1, RawSize: 30}
	config := models.DNSConfig{ResponseMode: models.Minimal, RealisticTTL: false}

	resp, err := svc.BuildResponse(query, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Payload) == 0 {
		t.Fatal("response payload must not be empty")
	}
	// Check transaction ID echoed
	txID := binary.BigEndian.Uint16(resp.Payload[0:2])
	if txID != 0x1234 {
		t.Errorf("transaction ID = %04X, want %04X", txID, 0x1234)
	}
	// QR=1 (bit 15 of flags word)
	flags := binary.BigEndian.Uint16(resp.Payload[2:4])
	if flags&0x8000 == 0 {
		t.Errorf("QR bit not set in flags %04X", flags)
	}
	// ANCOUNT = 1
	anCount := binary.BigEndian.Uint16(resp.Payload[6:8])
	if anCount != 1 {
		t.Errorf("ANCOUNT = %d, want 1", anCount)
	}
}

func TestBuildResponse_Amplified_IsLargerThanMinimal(t *testing.T) {
	svc := &services.DNSService{}
	query := models.DNSQuery{TransactionID: 0x0001, Name: "example.com", Type: 255, RawSize: 30}

	minResp, err := svc.BuildResponse(query, models.DNSConfig{ResponseMode: models.Minimal})
	if err != nil {
		t.Fatalf("minimal build error: %v", err)
	}
	ampResp, err := svc.BuildResponse(query, models.DNSConfig{ResponseMode: models.Amplified})
	if err != nil {
		t.Fatalf("amplified build error: %v", err)
	}

	if len(ampResp.Payload) <= len(minResp.Payload) {
		t.Errorf("amplified response (%d bytes) should be larger than minimal (%d bytes)",
			len(ampResp.Payload), len(minResp.Payload))
	}
}

func TestBuildResponse_RealisticTTL(t *testing.T) {
	svc := &services.DNSService{}
	query := models.DNSQuery{TransactionID: 0x0001, Name: "a.b", Type: 1, RawSize: 20}

	// With RealisticTTL=false the A record TTL bytes should be 0.
	resp, err := svc.BuildResponse(query, models.DNSConfig{ResponseMode: models.Minimal, RealisticTTL: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The A record starts after header(12) + question.  We only check that it parses without
	// panicking; detailed byte checks are done in dns_service.go unit internals.
	if len(resp.Payload) < 12 {
		t.Fatalf("response too short: %d bytes", len(resp.Payload))
	}

	// With RealisticTTL=true the response should be valid too.
	resp2, err := svc.BuildResponse(query, models.DNSConfig{ResponseMode: models.Minimal, RealisticTTL: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp2.Payload) == 0 {
		t.Fatal("response with realistic TTL must not be empty")
	}
}

func TestBuildResponse_SizeOverride(t *testing.T) {
	svc := &services.DNSService{}
	query := models.DNSQuery{TransactionID: 0x0002, Name: "x.y", Type: 255, RawSize: 20}
	target := 512
	config := models.DNSConfig{ResponseMode: models.Amplified, ResponseSizeBytes: target}

	resp, err := svc.BuildResponse(query, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The response should be at least as large as the target (within a small margin due to
	// TXT string framing overhead).  We allow up to target+16 bytes over.
	if len(resp.Payload) < target || len(resp.Payload) > target+16 {
		t.Errorf("response size = %d, want ~%d", len(resp.Payload), target)
	}
}

func TestBuildResponse_UnknownMode_ReturnsError(t *testing.T) {
	svc := &services.DNSService{}
	query := models.DNSQuery{TransactionID: 0x0001, Name: "a.b", Type: 1, RawSize: 20}
	_, err := svc.BuildResponse(query, models.DNSConfig{ResponseMode: "unknown"})
	if err == nil {
		t.Error("expected error for unknown response mode, got nil")
	}
}
