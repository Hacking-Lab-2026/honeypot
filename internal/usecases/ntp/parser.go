package ntp

import (
	"encoding/binary"
	"fmt"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

// ParseNTPRequest parses the NTP header from a UDP payload.
// Different NTP modes have different minimum sizes:
// 1-5: 48 bytes
// 6  : 12 bytes (control header, UNSUPPORTED)
// 7  : 8 bytes (private header, MONLIST)
func ParseNTPRequest(data []byte) (*models.NTPQuery, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("ntp packet empty")
	}

	b0 := data[0]
	li := (b0 >> 6) & 0x3
	vn := (b0 >> 3) & 0x7
	mode := b0 & 0x7

	q := &models.NTPQuery{
		LI:      li,
		VN:      vn,
		Mode:    mode,
		RawSize: len(data),
	}

	switch mode {
	case 7:
		// Private mode: 8-byte header
		if len(data) < 8 {
			return nil, fmt.Errorf("ntp mode 7 packet too short: %d bytes", len(data))
		}
		q.ReqCode = data[3]
		return q, nil

	case 6:
		// Control mode: 12-byte header
		if len(data) < 12 {
			return nil, fmt.Errorf("ntp mode 6 packet too short: %d bytes", len(data))
		}
		q.ReqCode = (data[3]) & 0x1f
		return q, nil

	default:
		// Modes 1-5: standard 48-byte NTP packet
		if len(data) < 48 {
			return nil, fmt.Errorf("ntp packet too short: %d bytes", len(data))
		}
		q.Stratum = data[1]
		q.Poll = int8(data[2])
		q.Precision = int8(data[3])
		q.TransmitTimestamp = binary.BigEndian.Uint64(data[40:48])
		return q, nil
	}
}
