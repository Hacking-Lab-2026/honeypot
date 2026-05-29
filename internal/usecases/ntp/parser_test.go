package ntp

import (
	"encoding/binary"
	"testing"
)

func TestParseNTPRequest_Valid(t *testing.T) {
	// Build a minimal 48-byte NTP request with VN=4 Mode=3 and a known transmit timestamp.
	pkt := make([]byte, 48)
	pkt[0] = byte((0 << 6) | ((4 & 0x7) << 3) | (3 & 0x7))
	// set transmit timestamp at offset 40..47
	var tx uint64 = 0x0102030405060708
	binary.BigEndian.PutUint64(pkt[40:48], tx)

	q, err := ParseNTPRequest(pkt)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if q.VN != 4 {
		t.Fatalf("expected VN=4 got %d", q.VN)
	}
	if q.Mode != 3 {
		t.Fatalf("expected Mode=3 got %d", q.Mode)
	}
	if q.TransmitTimestamp != tx {
		t.Fatalf("expected tx=0x%x got 0x%x", tx, q.TransmitTimestamp)
	}
	if q.RawSize != 48 {
		t.Fatalf("expected RawSize=48 got %d", q.RawSize)
	}
}

func TestParseNTPRequest_TooShort(t *testing.T) {
	_, err := ParseNTPRequest([]byte{0x00, 0x01})
	if err == nil {
		t.Fatalf("expected error for short packet")
	}
}
