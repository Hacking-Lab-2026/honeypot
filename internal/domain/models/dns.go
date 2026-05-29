package models

import "time"

// ResponseMode controls how the DNS honeypot constructs replies.
type ResponseMode string

const (
	// Minimal returns a single A record — realistic, small response.
	Minimal ResponseMode = "minimal"
	// Amplified returns many large records to maximise the amplification factor.
	Amplified ResponseMode = "amplified"
)

// DNSConfig holds per-variant configuration for DNS response generation.
type DNSConfig struct {
	ResponseMode      ResponseMode `json:"response_mode"`
	ResponseSizeBytes int          `json:"response_size_bytes"` // 0 = no override
	RealisticTTL      bool         `json:"realistic_ttl"`
	RealisticPadding  bool         `json:"realistic_padding"`   // use plausible TXT content instead of repeated "A"
	ResponseTTL       int          `json:"response_ttl"`        // explicit TTL in seconds; 0 falls back to RealisticTTL
}

// DNSQuery holds fields parsed from an incoming DNS query packet.
type DNSQuery struct {
	TransactionID uint16
	Name          string
	Type          uint16 // 1=A, 15=MX, 16=TXT, 255=ANY
	RawSize       int    // size of the original UDP payload in bytes
}

// DNSResponse holds the wire-format bytes to send back to the querier.
type DNSResponse struct {
	Payload []byte
}

// DNSEvent records an observed DNS amplification probe.
type DNSEvent struct {
	ID                  string
	SourceIP            string
	SourcePort          int
	DestinationIP       string  // which of the honeypot's IPs the probe was sent to
	QueriedName         string
	QueryType           string // human-readable: "A", "ANY", "MX", …
	ResponsePayload     []byte
	ResponseSizeBytes   int
	Timestamp           time.Time
	VariantID           string
	ServiceName         string  // protocol/honeypot type, e.g. "dns"
	ProbeType           string  `json:"probe_type"` // "scanner", "attacker", "noise"
	AmplificationFactor float64 // ResponseSizeBytes / request size
}
