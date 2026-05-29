package dns

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

const minDNSMessageSize = 12 // DNS header is always 12 bytes

// ParseQuery parses a raw UDP payload into a DNSQuery.
// It extracts the transaction ID, QNAME, and QTYPE from the first question.
// Compression pointers are rejected because they must not appear in query QNAME fields
// per RFC 1035 Â§4.1.4 (only used in answers).
func ParseQuery(data []byte) (models.DNSQuery, error) {
	if len(data) < minDNSMessageSize {
		return models.DNSQuery{}, fmt.Errorf("DNS message too short: %d bytes (minimum %d)", len(data), minDNSMessageSize)
	}

	txID := binary.BigEndian.Uint16(data[0:2])
	qdCount := binary.BigEndian.Uint16(data[4:6])
	if qdCount == 0 {
		return models.DNSQuery{}, fmt.Errorf("DNS query has no questions (QDCOUNT=0)")
	}

	name, offset, err := parseQName(data, minDNSMessageSize)
	if err != nil {
		return models.DNSQuery{}, fmt.Errorf("failed to parse QNAME: %w", err)
	}

	if offset+4 > len(data) {
		return models.DNSQuery{}, fmt.Errorf("DNS message truncated after QNAME (need 4 more bytes for QTYPE/QCLASS)")
	}

	qtype := binary.BigEndian.Uint16(data[offset : offset+2])

	return models.DNSQuery{
		TransactionID: txID,
		Name:          name,
		Type:          qtype,
		RawSize:       len(data),
	}, nil
}

// parseQName reads a DNS label-encoded name starting at offset and returns the
// decoded name string and the offset immediately after the terminating zero byte.
func parseQName(data []byte, offset int) (string, int, error) {
	var labels []string
	for {
		if offset >= len(data) {
			return "", 0, fmt.Errorf("QNAME extends past end of message at offset %d", offset)
		}
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}
		// Top two bits set indicate a compression pointer â€” not expected in queries.
		if length&0xC0 != 0 {
			return "", 0, fmt.Errorf("unexpected label type 0x%02X at offset %d (compression pointers not allowed in queries)", data[offset], offset)
		}
		offset++
		if offset+length > len(data) {
			return "", 0, fmt.Errorf("label of length %d at offset %d extends past end of message", length, offset-1)
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(labels, "."), offset, nil
}
