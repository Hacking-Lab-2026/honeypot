package ntp

import (
	"encoding/binary"
	"fmt"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

// ParseNTPRequest parses the minimal NTP header from a UDP payload.
// Returns an NTPQuery with selected fields. Expects at least 48 bytes.
func ParseNTPRequest(data []byte) (*models.NTPQuery, error) {
	if len(data) < 48 {
		return nil, fmt.Errorf("ntp packet too short: %d bytes", len(data))
	}

	b0 := data[0]
	li := (b0 >> 6) & 0x3
	vn := (b0 >> 3) & 0x7
	mode := b0 & 0x7

	stratum := data[1]
	poll := int8(data[2])
	precision := int8(data[3])

	// Transmit Timestamp is at offset 40..47
	tx := binary.BigEndian.Uint64(data[40:48])

	q := &models.NTPQuery{
		LI:                li,
		VN:                vn,
		Mode:              mode,
		Stratum:           stratum,
		Poll:              poll,
		Precision:         precision,
		TransmitTimestamp: tx,
		RawSize:           len(data),
	}
	return q, nil
}
