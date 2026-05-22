package services

import (
	"encoding/binary"
	"time"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

const (
	ntpPacketSize = 48
	// UNIX -> NTP consts
	unixToNtpSeconds = 2208988800
)

type NTPService struct{}

// BuildResponse constructs a timestamp-only NTP reply.
// Echoes the client transmit timestamp into Originate, sets Receive and Transmit timestamps to now.
func (s *NTPService) BuildResponse(query *models.NTPQuery) (models.NTPResponse, error) {
	now := time.Now().UTC()
	recv := timeToNtp(now)
	tx := timeToNtp(now)

	resp := make([]byte, ntpPacketSize)

	// LI=0, VN = query.VN, Mode=4 (server)
	vn := query.VN
	if vn == 0 {
		vn = 4
	}
	resp[0] = byte((0 << 6) | ((vn & 0x7) << 3) | (4 & 0x7))
	resp[1] = 2         // stratum 2 not direct time authority
	resp[2] = byte(6)   // poll
	resp[3] = byte(236) // precision

	// Reference Timestamp
	binary.BigEndian.PutUint64(resp[16:24], recv)

	// Originate Timestamp, copy from query
	binary.BigEndian.PutUint64(resp[24:32], query.TransmitTimestamp)

	// Receive Timestamp
	binary.BigEndian.PutUint64(resp[32:40], recv)

	// Transmit Timestamp
	binary.BigEndian.PutUint64(resp[40:48], tx)

	return models.NTPResponse{Payload: resp}, nil
}

func timeToNtp(t time.Time) uint64 {
	secs := uint64(t.Unix() + unixToNtpSeconds)
	frac := uint64((float64(t.Nanosecond()) / 1e9) * (1 << 32))
	return (secs << 32) | (frac & 0xffffffff)
}
