package services

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

func TestNTPService_BuildResponse_EchoOriginate(t *testing.T) {
	svc := &NTPService{}
	q := &models.NTPQuery{}
	// client's transmit timestamp
	tx := uint64(0x1234567887654321)
	q.TransmitTimestamp = tx

	resp, err := svc.BuildResponse(q)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Payload) != 48 {
		t.Fatalf("expected 48-byte response got %d", len(resp.Payload))
	}
	// Originate timestamp is at offset 24..31 and should equal client's tx
	got := binary.BigEndian.Uint64(resp.Payload[24:32])
	if got != tx {
		t.Fatalf("expected originate=0x%x got 0x%x", tx, got)
	}
	// Transmit timestamp should be non-zero and recent
	tx2 := binary.BigEndian.Uint64(resp.Payload[40:48])
	if tx2 == 0 {
		t.Fatalf("expected non-zero transmit timestamp")
	}
	// quick sanity: convert transmit to unix seconds and check it's near now
	secs := int64((tx2 >> 32) - unixToNtpSeconds)
	if time.Since(time.Unix(secs, 0)) > time.Minute*5 {
		t.Fatalf("transmit timestamp not recent")
	}
}
