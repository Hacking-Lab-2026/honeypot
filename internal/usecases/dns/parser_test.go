package dns_test

import (
	"encoding/binary"
	"strings"
	"testing"

	dnsusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/dns"
)

// buildRawQuery constructs a minimal but valid DNS query wire-format message.
func buildRawQuery(txID uint16, name string, qtype uint16) []byte {
	// 12-byte header
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], txID)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // RD=1, standard query
	binary.BigEndian.PutUint16(msg[4:6], 1)       // QDCOUNT=1

	// QNAME in label format
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0) // root label terminator

	// QTYPE and QCLASS
	qt := make([]byte, 2)
	binary.BigEndian.PutUint16(qt, qtype)
	msg = append(msg, qt...)
	msg = append(msg, 0x00, 0x01) // CLASS = IN

	return msg
}

func TestParseQuery_Valid(t *testing.T) {
	raw := buildRawQuery(0xABCD, "example.com", 1)
	q, err := dnsusecase.ParseQuery(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.TransactionID != 0xABCD {
		t.Errorf("TransactionID = %04X, want ABCD", q.TransactionID)
	}
	if q.Name != "example.com" {
		t.Errorf("Name = %q, want %q", q.Name, "example.com")
	}
	if q.Type != 1 {
		t.Errorf("Type = %d, want 1 (A)", q.Type)
	}
	if q.RawSize != len(raw) {
		t.Errorf("RawSize = %d, want %d", q.RawSize, len(raw))
	}
}

func TestParseQuery_AnyType(t *testing.T) {
	raw := buildRawQuery(0x0001, "test.local", 255)
	q, err := dnsusecase.ParseQuery(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if q.Type != 255 {
		t.Errorf("Type = %d, want 255 (ANY)", q.Type)
	}
	if q.Name != "test.local" {
		t.Errorf("Name = %q, want %q", q.Name, "test.local")
	}
}

func TestParseQuery_TooShort(t *testing.T) {
	_, err := dnsusecase.ParseQuery([]byte{0x00, 0x01, 0x00})
	if err == nil {
		t.Error("expected error for truncated message, got nil")
	}
}

func TestParseQuery_EmptyPayload(t *testing.T) {
	_, err := dnsusecase.ParseQuery([]byte{})
	if err == nil {
		t.Error("expected error for empty payload, got nil")
	}
}

func TestParseQuery_NoQuestions(t *testing.T) {
	// Valid header but QDCOUNT=0
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:6], 0) // QDCOUNT=0
	_, err := dnsusecase.ParseQuery(msg)
	if err == nil {
		t.Error("expected error for QDCOUNT=0, got nil")
	}
}

func TestParseQuery_TruncatedAfterQName(t *testing.T) {
	// Build a message with QNAME but no QTYPE/QCLASS
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:6], 1) // QDCOUNT=1
	msg = append(msg, 3, 'f', 'o', 'o', 0)  // QNAME = "foo"
	// No QTYPE/QCLASS
	_, err := dnsusecase.ParseQuery(msg)
	if err == nil {
		t.Error("expected error for message truncated after QNAME, got nil")
	}
}

func TestParseQuery_CompressionPointerRejected(t *testing.T) {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:6], 1) // QDCOUNT=1
	// Label with top two bits set = compression pointer
	msg = append(msg, 0xC0, 0x0C)
	_, err := dnsusecase.ParseQuery(msg)
	if err == nil {
		t.Error("expected error for compression pointer in query, got nil")
	}
}
