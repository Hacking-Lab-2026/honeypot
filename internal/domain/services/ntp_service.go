package services

import (
	"encoding/binary"
	"time"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

const (
	ntpPacketSize        = 48
	unixToNtpSeconds     = 2208988800
	ntpPrivateHeaderSize = 8
	monGetlist1ItemSize  = 72
	itemsPerMonlistPkt   = 6 // ntpd default for MON_GETLIST_1
)

type NTPService struct{}

// constructs an NTP reply based on the query mode and variant config.
//
// Mode 3 (client): standard server response (mode 4 out), no amplification.
// Mode 6 (control): not implemented; returns empty (no response sent).
// Mode 7 (private/monlist): amplified response, behavior controlled by cfg.
//
// For any other mode, returns an empty response (handler will skip sending).
func (s *NTPService) BuildResponse(query *models.NTPQuery, cfg models.NTPConfig) (models.NTPResponse, error) {
	switch query.Mode {
	case 3:
		return s.buildModeServerResponse(query)
	case 7:
		return s.buildMonlistResponse(query, cfg)
	default:
		// Mode 6 (control) and anything else: no response.
		return models.NTPResponse{}, nil
	}
}

// constructs a standard mode 4 server response to a mode 3 client request
func (s *NTPService) buildModeServerResponse(query *models.NTPQuery) (models.NTPResponse, error) {
	now := time.Now().UTC()
	recv := timeToNtp(now)
	tx := timeToNtp(now)

	resp := make([]byte, ntpPacketSize)

	vn := query.VN
	if vn == 0 {
		vn = 4
	}
	// LI=0, VN=vn, Mode=4 (server)
	resp[0] = byte((0 << 6) | ((vn & 0x7) << 3) | 4)
	resp[1] = 2    // stratum 2
	resp[2] = 6    // poll
	resp[3] = 0xEC // precision (-20)

	// Reference Timestamp
	binary.BigEndian.PutUint64(resp[16:24], recv)
	// Originate Timestamp (copy from client's transmit)
	binary.BigEndian.PutUint64(resp[24:32], query.TransmitTimestamp)
	// Receive Timestamp
	binary.BigEndian.PutUint64(resp[32:40], recv)
	// Transmit Timestamp
	binary.BigEndian.PutUint64(resp[40:48], tx)

	return models.SinglePacketResponse(resp), nil
}

// dispatches on cfg.ResponseMode.
// "minimal": single empty monlist packet (looks like a patched/non-vulnerable ntpd)
// "amplified" (or anything else): full multi-packet monlist with cfg.NumPeers fake clients
func (s *NTPService) buildMonlistResponse(query *models.NTPQuery, cfg models.NTPConfig) (models.NTPResponse, error) {
	if cfg.ResponseMode != "amplified" {
		return s.buildShortMonlistResponse(query)
	}
	numPeers := cfg.NumPeers
	if numPeers <= 0 {
		numPeers = 36 // 6 packets × 6 items default
	}
	return s.buildAmplifiedMonlistResponse(query, numPeers)
}

// returns a single mode 7 packet with zero items
// Mimics a patched ntpd that responds but doesn't leak monitor data
func (s *NTPService) buildShortMonlistResponse(query *models.NTPQuery) (models.NTPResponse, error) {
	pkt := make([]byte, ntpPrivateHeaderSize)
	vn := query.VN
	if vn == 0 {
		vn = 2
	}
	// Byte 0: R=1 (response), M=0 (last), VN, Mode=7
	pkt[0] = 0x80 | ((vn & 0x7) << 3) | 7
	pkt[1] = 0  // auth=0, seq=0
	pkt[2] = 3  // implementation = IMPL_XNTPD
	pkt[3] = 42 // request code = REQ_MON_GETLIST_1
	// items=0, item_size=0 (bytes 4-7 already zero)

	return models.SinglePacketResponse(pkt), nil
}

// generates a full multi-packet monlist response
// with `numPeers` fake client entries distributed across multiple UDP datagrams
func (s *NTPService) buildAmplifiedMonlistResponse(query *models.NTPQuery, numPeers int) (models.NTPResponse, error) {
	numPackets := (numPeers + itemsPerMonlistPkt - 1) / itemsPerMonlistPkt
	packets := make([][]byte, 0, numPackets)

	peersRemaining := numPeers
	peerIdx := 0
	for pktIdx := 0; pktIdx < numPackets; pktIdx++ {
		itemsThisPkt := itemsPerMonlistPkt
		if peersRemaining < itemsPerMonlistPkt {
			itemsThisPkt = peersRemaining
		}
		isLast := pktIdx == numPackets-1

		pkt := s.buildMonlistPacket(query, itemsThisPkt, isLast, pktIdx, peerIdx)
		packets = append(packets, pkt)

		peersRemaining -= itemsThisPkt
		peerIdx += itemsThisPkt
	}

	return models.NTPResponse{Packets: packets}, nil
}

// builds a single monlist response datagram
// `numItems` is how many fake peers this packet carries
// `isLast` controls the M (more) flag
// `seq` is the packet sequence number
// `peerStartIdx` is the global index of the first peer in this packet (used to vary the fake data)
func (s *NTPService) buildMonlistPacket(query *models.NTPQuery, numItems int, isLast bool, seq int, peerStartIdx int) []byte {
	pkt := make([]byte, ntpPrivateHeaderSize+numItems*monGetlist1ItemSize)

	vn := query.VN
	if vn == 0 {
		vn = 2
	}

	// Byte 0: R=1, M=(0 or 1), VN, Mode=7
	moreFlag := byte(0x40) // M=1 if more packets follow
	if isLast {
		moreFlag = 0
	}
	pkt[0] = 0x80 | moreFlag | ((vn & 0x7) << 3) | 7

	// Byte 1: Auth=0, Sequence in low 7 bits
	pkt[1] = byte(seq & 0x7F)

	// Byte 2: Implementation = 3 (IMPL_XNTPD)
	pkt[2] = 3

	// Byte 3: Request code = 42 (REQ_MON_GETLIST_1)
	pkt[3] = 42

	// Bytes 4-5: Err (4 bits, =0) + Number of items (12 bits)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(numItems)&0x0FFF)

	// Bytes 6-7: MBZ (4 bits, =0) + Item size (12 bits)
	binary.BigEndian.PutUint16(pkt[6:8], uint16(monGetlist1ItemSize)&0x0FFF)

	// Items
	now := uint32(time.Now().Unix())
	for i := 0; i < numItems; i++ {
		offset := ntpPrivateHeaderSize + i*monGetlist1ItemSize
		s.writeMonitorItem(pkt[offset:offset+monGetlist1ItemSize], peerStartIdx+i, now)
	}

	return pkt
}

// writes a single 72-byte info_monitor_1 record
// Uses addresses in 192.0.2.0/24 (TEST-NET-1, RFC 5737) for the fake clients
func (s *NTPService) writeMonitorItem(dst []byte, idx int, now uint32) {
	// firsttime: seconds since stats reset (fake)
	binary.BigEndian.PutUint32(dst[0:4], 3600+uint32(idx*10))

	// lasttime: seconds since last packet from this client (fake)
	binary.BigEndian.PutUint32(dst[4:8], uint32(idx))

	// restr: restriction mask
	binary.BigEndian.PutUint32(dst[8:12], 0)

	// count: packets received from this client (fake)
	binary.BigEndian.PutUint32(dst[12:16], uint32(100+idx))

	// addr: fake IPv4 in TEST-NET-1 (192.0.2.0/24, never globally routable)
	dst[16] = 192
	dst[17] = 0
	dst[18] = 2
	dst[19] = byte(idx % 256)

	// daddr: our local interface address (placeholder)
	dst[20] = 10
	dst[21] = 0
	dst[22] = 0
	dst[23] = 1

	// flags
	binary.BigEndian.PutUint32(dst[24:28], 0x0001)

	// port: NTP
	binary.BigEndian.PutUint16(dst[28:30], 123)

	// mode: client mode 3
	dst[30] = 3

	// version: NTPv4
	dst[31] = 4

	// v6_flag: 0 (this is IPv4)
	dst[32] = 0

	// bytes 33-71 left zero (unused for IPv4 entries)
}

// timeToNtp converts a Go time to NTP 64-bit timestamp format
func timeToNtp(t time.Time) uint64 {
	secs := uint64(t.Unix() + unixToNtpSeconds)
	frac := uint64((float64(t.Nanosecond()) / 1e9) * (1 << 32))
	return (secs << 32) | (frac & 0xffffffff)
}
