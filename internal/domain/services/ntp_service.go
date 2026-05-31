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

// BuildResponse constructs an NTP reply based on the query mode.
// Mode 3 (server): timestamp-only reply
// Mode 6 (control): NTP control message reply
// Mode 7 (private/monlist): amplified peer list
func (s *NTPService) BuildResponse(query *models.NTPQuery) (models.NTPResponse, error) {
	switch query.Mode {
	case 3:
		return s.buildModeServerResponse(query)
	case 6:
		return s.buildModeControlResponse(query)
	case 7:
		return s.buildModePrivateResponse(query)
	default:
		return s.buildModeServerResponse(query)
	}
}

// buildModeServerResponse constructs a standard NTP server response (mode 4).
func (s *NTPService) buildModeServerResponse(query *models.NTPQuery) (models.NTPResponse, error) {
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

// buildModeControlResponse constructs an NTP control message response (mode 6).
func (s *NTPService) buildModeControlResponse(query *models.NTPQuery) (models.NTPResponse, error) {
	// NTP control message format
	// Byte 0: LI(2) VN(3) Mode(3) = 0b01_100_110 for response = 0xC6
	// Byte 1: Response, Error, More (R E M)
	// Bytes 2-3: Sequence number
	// Bytes 4-5: Status (NONCE)
	// Bytes 6-9: Association ID
	// Bytes 10-11: Offset
	// Bytes 12-13: Count
	// Bytes 14+: Data

	resp := make([]byte, 48)

	// Set header
	resp[0] = 0xC6 // LI=0, VN=4, Mode=6 (response)
	resp[1] = 0x80 // Response flag set
	// seq, status, assoc_id left as zeros for simplicity

	return models.NTPResponse{Payload: resp}, nil
}

// buildModePrivateResponse constructs a monlist amplification response (mode 7).
func (s *NTPService) buildModePrivateResponse(query *models.NTPQuery) (models.NTPResponse, error) {
	return s.buildModePrivateMonlistResponse(query)
}

func timeToNtp(t time.Time) uint64 {
	secs := uint64(t.Unix() + unixToNtpSeconds)
	frac := uint64((float64(t.Nanosecond()) / 1e9) * (1 << 32))
	return (secs << 32) | (frac & 0xffffffff)
}

// buildModePrivateResponse returns a properly formatted monlist response for mode 7.
// This generates a large amplified response with fake peer records.
func (s *NTPService) buildModePrivateMonlistResponse(query *models.NTPQuery) (models.NTPResponse, error) {
	now := time.Now().UTC()
	nowNtp := timeToNtp(now)

	// Pre-allocate response buffer (header + 20 records × 80 bytes)
	resp := make([]byte, 2+20*80)

	// Header byte: LI=0, VN=query.VN, Mode=7
	headerByte := byte((0 << 6) | ((query.VN & 0x7) << 3) | (7 & 0x7))
	resp[0] = headerByte
	resp[1] = 0 // implementation byte

	// Add 20 fake peer records (each exactly 80 bytes)
	for i := 0; i < 20; i++ {
		offset := 2 + i*80
		record := resp[offset : offset+80]

		// Peer address (4 bytes IP)
		record[0] = 192
		record[1] = 168
		record[2] = uint8(i % 256)
		record[3] = uint8(i)

		// Port (2 bytes)
		binary.BigEndian.PutUint16(record[4:6], 123)

		// Stratum (1 byte)
		record[6] = byte(2 + (i % 10))

		// Poll interval (1 byte)
		record[7] = 6

		// Precision (1 byte)
		record[8] = 0xF6

		// Association ID (4 bytes)
		binary.BigEndian.PutUint32(record[9:13], uint32(i+1000))

		// Status (1 byte)
		record[13] = 0x44

		// TTL (1 byte)
		record[14] = 64

		// Reach (1 byte)
		record[15] = 0xFF

		// Unreach (1 byte)
		record[16] = 0

		// hmode (1 byte)
		record[17] = 1

		// pmode (1 byte)
		record[18] = 4

		// hpoll (1 byte)
		record[19] = 6

		// ppoll (1 byte)
		record[20] = 6

		// Reserved (1 byte)
		record[21] = 0

		// Delay (4 bytes)
		binary.BigEndian.PutUint32(record[22:26], uint32(10000+i*1000))

		// Offset (4 bytes)
		binary.BigEndian.PutUint32(record[26:30], uint32(i*100))

		// Dispersion (4 bytes)
		binary.BigEndian.PutUint32(record[30:34], uint32(5000+i*500))

		// Jitter (4 bytes)
		binary.BigEndian.PutUint32(record[34:38], uint32(100+i*10))

		// Timestamp field (8 bytes)
		binary.BigEndian.PutUint64(record[38:46], nowNtp)

		// Padding (34 bytes remaining to fill 80)
	}

	return models.NTPResponse{Payload: resp}, nil
}
