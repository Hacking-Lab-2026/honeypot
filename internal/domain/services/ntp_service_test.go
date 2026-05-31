package services

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

func TestNTPService_BuildResponse_EchoOriginate(t *testing.T) {
	svc := &NTPService{}
	q := &models.NTPQuery{
		Mode: 3, // client mode
		VN:   4,
	}
	// client's transmit timestamp
	tx := uint64(0x1234567887654321)
	q.TransmitTimestamp = tx
	config := models.NTPConfig{ResponseMode: "minimal"}

	resp, err := svc.BuildResponse(q, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Packets) == 0 {
		t.Fatalf("expected at least one packet in response")
	}
	payload := resp.Packets[0]
	if len(payload) != 48 {
		t.Fatalf("expected 48-byte response got %d", len(payload))
	}
	// Originate timestamp is at offset 24..31 and should equal client's tx
	got := binary.BigEndian.Uint64(payload[24:32])
	if got != tx {
		t.Fatalf("expected originate=0x%x got 0x%x", tx, got)
	}
	// Transmit timestamp should be non-zero and recent
	tx2 := binary.BigEndian.Uint64(payload[40:48])
	if tx2 == 0 {
		t.Fatalf("expected non-zero transmit timestamp")
	}
	// quick sanity: convert transmit to unix seconds and check it's near now
	secs := int64((tx2 >> 32) - unixToNtpSeconds)
	if time.Since(time.Unix(secs, 0)) > time.Minute*5 {
		t.Fatalf("transmit timestamp not recent")
	}
}

func TestNTPService_Mode6Control(t *testing.T) {
	svc := &NTPService{}
	query := &models.NTPQuery{
		Mode: 6,
		VN:   4,
	}
	config := models.NTPConfig{ResponseMode: "minimal"}

	resp, err := svc.BuildResponse(query, config)
	if err != nil {
		t.Fatalf("BuildResponse failed: %v", err)
	}
	// Mode 6 is not implemented; expects empty response
	if len(resp.Packets) != 0 {
		t.Errorf("Mode 6 should return empty response, got %d packets", len(resp.Packets))
	}
}

func TestNTPService_Mode7Monlist(t *testing.T) {
	svc := &NTPService{}
	query := &models.NTPQuery{
		Mode: 7,
		VN:   4,
	}
	config := models.NTPConfig{ResponseMode: "amplified", NumPeers: 20}

	resp, err := svc.BuildResponse(query, config)
	if err != nil {
		t.Fatalf("BuildResponse failed: %v", err)
	}
	if len(resp.Packets) == 0 {
		t.Fatalf("expected at least one packet in response")
	}

	// Sum total payload across all packets
	totalSize := 0
	for _, pkt := range resp.Packets {
		totalSize += len(pkt)
	}

	// 20 peers: (20 + 6 - 1) / 6 = 4 packets
	// Each packet: 8-byte header + up to 6 items × 72 bytes
	// Total = 8 header + 20*72 item bytes = 1448 bytes
	expectedSize := 8 + 20*72
	if totalSize != expectedSize {
		t.Errorf("Mode 7 response size mismatch: got %d bytes, want %d", totalSize, expectedSize)
	}

	// Check first packet header: should be mode 7 with M flag set (more packets)
	mode := resp.Packets[0][0] & 0x7
	if mode != 7 {
		t.Errorf("Mode 7 header byte mismatch: got mode %d, want 7", mode)
	}
}
