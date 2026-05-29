package services

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
)

const (
	dnsHeaderSize = 12

	// Compression pointer back to offset 12 (start of the question's QNAME).
	dnsPtrByte0 = 0xC0
	dnsPtrByte1 = 0x0C

	dnsTypeA   uint16 = 1
	dnsTypeTXT uint16 = 16
	dnsClassIN uint16 = 1

	// 203.0.113.1 â€” TEST-NET-3 (RFC 5737), documentation-only range.
	aIP0 byte = 203
	aIP1 byte = 0
	aIP2 byte = 113
	aIP3 byte = 1

	// Default amplified-mode parameters.
	amplifiedTXTCount   = 10
	amplifiedTXTPayload = 200

	realisticTTL uint32 = 300
)

// realisticTXTPayloads contains 9 plausible DNS TXT record strings, each padded to exactly
// 200 bytes. They mimic SPF, DKIM, and domain-verification records seen on real domains,
// making amplified responses less obviously synthetic when inspected by an attacker.
var realisticTXTPayloads = func() [9]string {
	pad := func(s string) string {
		if len(s) >= 200 {
			return s[:200]
		}
		return s + strings.Repeat(" ", 200-len(s))
	}
	return [9]string{
		pad("v=spf1 include:_spf.google.com include:_spf.mailgun.org include:sendgrid.net include:amazonses.com ip4:198.51.100.0/24 ip4:203.0.113.0/24 ~all"),
		pad("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3vwBmNdrTmcYUmwxbZiNoRMNaFexaVQd8LKbTRKQgF7z4k2wPjmDlNqzRMoSBhEAJ3wXkMLr5tY8nQVpPl"),
		pad("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxK7iHB3bzNqfEIJYO2kVHT5bWqhDrLw7zsMSo6R9cFxDjEuVLqtBW1g8ypNfGSIXsK4mLUoQwR3zPHXmyA"),
		pad("google-site-verification=dBw5CvburAxi537Rp88QkifsB-i2Ht5-CagA9b22gAPq3GDFsAbcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
		pad("MS=ms23456789; facebook-domain-verification=abcdef1234567890abcdef1234; adobe-idp-site-verification=AABBCCDDEEFF00112233445566778899"),
		pad("v=DKIM1; k=rsa; h=sha256; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPnNvOorHkLBdFBqc3QHpQMrk2bWxLZ9zJkGpS8NTmOyFxE6VuRedQiI3AqsKlTbnMwz"),
		pad("amazonses:ZGVmYXVsdA==ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu"),
		pad("docusign=1b0a6754-49b1-4db5-8540-d2c12664b289; stripe-verification=ABCDEF1234567890abcdef1234567890ABCDEF123456"),
		pad("v=spf1 include:spf.protection.outlook.com include:mail.zendesk.com include:_spf.salesforce.com include:mktomail.com ip4:192.0.2.0/24 ~all"),
	}
}()

// DNSService builds DNS wire-format responses for the honeypot.
// It contains only pure logic and has no knowledge of sockets or persistence.
type DNSService struct{}

// BuildResponse constructs a DNS reply according to the provided config.
func (s *DNSService) BuildResponse(query models.DNSQuery, config models.DNSConfig) (models.DNSResponse, error) {
	var ttl uint32
	switch {
	case config.ResponseTTL > 0:
		ttl = uint32(config.ResponseTTL)
	case config.RealisticTTL:
		ttl = realisticTTL
	}

	encodedName := encodeDNSName(query.Name)
	question := buildQuestion(encodedName, query.Type)

	if config.ResponseSizeBytes > 0 {
		return s.buildSizedResponse(query.TransactionID, question, ttl, config.ResponseSizeBytes)
	}

	switch config.ResponseMode {
	case models.Minimal:
		return s.buildMinimalResponse(query.TransactionID, question, ttl)
	case models.Amplified:
		return s.buildAmplifiedResponse(query.TransactionID, question, ttl, config.RealisticPadding)
	default:
		return models.DNSResponse{}, fmt.Errorf("unknown response mode: %q", config.ResponseMode)
	}
}

// buildMinimalResponse returns one A record â€” small and realistic.
func (s *DNSService) buildMinimalResponse(txID uint16, question []byte, ttl uint32) (models.DNSResponse, error) {
	payload := assembleResponse(txID, 1, question, buildARecord(ttl))
	return models.DNSResponse{Payload: payload}, nil
}

// buildAmplifiedResponse returns one A record plus many large TXT records.
// When realisticPadding is true the TXT content uses plausible DNS strings;
// otherwise it falls back to repeated "A" characters.
func (s *DNSService) buildAmplifiedResponse(txID uint16, question []byte, ttl uint32, realisticPadding bool) (models.DNSResponse, error) {
	var answers []byte
	answers = append(answers, buildARecord(ttl)...)
	for i := 0; i < amplifiedTXTCount-1; i++ {
		var text string
		if realisticPadding {
			text = realisticTXTPayloads[i]
		} else {
			text = strings.Repeat("A", amplifiedTXTPayload)
		}
		answers = append(answers, buildTXTRecord(ttl, text)...)
	}
	payload := assembleResponse(txID, amplifiedTXTCount, question, answers)
	return models.DNSResponse{Payload: payload}, nil
}

// buildSizedResponse pads the response to approximately targetSize bytes.
func (s *DNSService) buildSizedResponse(txID uint16, question []byte, ttl uint32, targetSize int) (models.DNSResponse, error) {
	aRecord := buildARecord(ttl)
	baseline := assembleResponse(txID, 1, question, aRecord)

	if targetSize <= len(baseline) {
		return models.DNSResponse{Payload: baseline}, nil
	}

	remaining := targetSize - len(baseline)
	txtRecord := buildTXTRecordOfSize(ttl, remaining)

	var answers []byte
	answers = append(answers, aRecord...)
	answers = append(answers, txtRecord...)
	payload := assembleResponse(txID, 2, question, answers)
	return models.DNSResponse{Payload: payload}, nil
}

// assembleResponse concatenates header + question + answers into a complete DNS message.
func assembleResponse(txID uint16, anCount uint16, question, answers []byte) []byte {
	header := buildDNSHeader(txID, anCount)
	msg := make([]byte, 0, len(header)+len(question)+len(answers))
	msg = append(msg, header...)
	msg = append(msg, question...)
	msg = append(msg, answers...)
	return msg
}

// buildDNSHeader builds the 12-byte DNS response header.
func buildDNSHeader(txID uint16, anCount uint16) []byte {
	h := make([]byte, dnsHeaderSize)
	binary.BigEndian.PutUint16(h[0:2], txID)
	binary.BigEndian.PutUint16(h[2:4], 0x8400) // QR=1, AA=1, RCODE=0
	binary.BigEndian.PutUint16(h[4:6], 1)       // QDCOUNT
	binary.BigEndian.PutUint16(h[6:8], anCount)  // ANCOUNT
	// NSCOUNT and ARCOUNT remain 0
	return h
}

// buildQuestion encodes the DNS question section.
func buildQuestion(encodedName []byte, qtype uint16) []byte {
	q := make([]byte, len(encodedName)+4)
	copy(q, encodedName)
	binary.BigEndian.PutUint16(q[len(encodedName):], qtype)
	binary.BigEndian.PutUint16(q[len(encodedName)+2:], uint16(dnsClassIN))
	return q
}

// buildARecord returns a 16-byte A resource record using a compression pointer.
func buildARecord(ttl uint32) []byte {
	r := make([]byte, 16)
	r[0] = dnsPtrByte0
	r[1] = dnsPtrByte1
	binary.BigEndian.PutUint16(r[2:4], uint16(dnsTypeA))
	binary.BigEndian.PutUint16(r[4:6], uint16(dnsClassIN))
	binary.BigEndian.PutUint32(r[6:10], ttl)
	binary.BigEndian.PutUint16(r[10:12], 4) // RDLENGTH = 4
	r[12] = aIP0
	r[13] = aIP1
	r[14] = aIP2
	r[15] = aIP3
	return r
}

// buildTXTRecord builds a TXT resource record for the given text (clamped to 255 bytes).
func buildTXTRecord(ttl uint32, text string) []byte {
	if len(text) > 255 {
		text = text[:255]
	}
	rdata := make([]byte, 1+len(text))
	rdata[0] = byte(len(text))
	copy(rdata[1:], text)
	return buildRR(dnsTypeTXT, ttl, rdata)
}

// buildTXTRecordOfSize builds a TXT record whose wire size is approximately targetBytes.
// TXT RDATA is packed as groups of (1-byte length + up to 255 bytes of data).
func buildTXTRecordOfSize(ttl uint32, targetBytes int) []byte {
	const rrOverhead = 12 // ptr(2) + type(2) + class(2) + ttl(4) + rdlen(2)
	rdataNeeded := targetBytes - rrOverhead
	if rdataNeeded <= 1 {
		return buildTXTRecord(ttl, "A")
	}
	var rdata []byte
	remaining := rdataNeeded
	for remaining > 1 {
		strLen := 255
		if remaining-1 < strLen {
			strLen = remaining - 1
		}
		if strLen <= 0 {
			break
		}
		rdata = append(rdata, byte(strLen))
		chunk := make([]byte, strLen)
		for i := range chunk {
			chunk[i] = 'A'
		}
		rdata = append(rdata, chunk...)
		remaining -= 1 + strLen
	}
	return buildRR(dnsTypeTXT, ttl, rdata)
}

// buildRR builds a resource record with the given type and RDATA, using a compression pointer for NAME.
func buildRR(rrType uint16, ttl uint32, rdata []byte) []byte {
	r := make([]byte, 12+len(rdata))
	r[0] = dnsPtrByte0
	r[1] = dnsPtrByte1
	binary.BigEndian.PutUint16(r[2:4], rrType)
	binary.BigEndian.PutUint16(r[4:6], uint16(dnsClassIN))
	binary.BigEndian.PutUint32(r[6:10], ttl)
	binary.BigEndian.PutUint16(r[10:12], uint16(len(rdata)))
	copy(r[12:], rdata)
	return r
}

// encodeDNSName converts a domain name string to DNS wire format (length-prefixed labels).
func encodeDNSName(name string) []byte {
	var buf []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0) // root label terminator
	return buf
}
