package models

import "time"

// controls how the DNS honeypot constructs replies
type ResponseMode string

const (
	// returns a single A record
	Minimal ResponseMode = "minimal"
	// returns many large records to maximise the amplification factor
	Amplified ResponseMode = "amplified"
)

type DNSConfig struct {
	ResponseMode      ResponseMode `json:"response_mode" yaml:"response_mode"`
	ResponseSizeBytes int          `json:"response_size_bytes" yaml:"response_size_bytes"`
	RealisticTTL      bool         `json:"realistic_ttl" yaml:"realistic_ttl"`
	RealisticPadding  bool         `json:"realistic_padding" yaml:"realistic_padding"`
	ResponseTTL       int          `json:"response_ttl" yaml:"response_ttl"`
}

// holds fields parsed from an incoming DNS query packet
type DNSQuery struct {
	TransactionID uint16
	Name          string
	Type          uint16 
	RawSize       int    // size of the original UDP payload in bytes
}

type DNSResponse struct {
	Payload []byte
}

type DNSEvent struct {
	ID                  string
	SourceIP            string
	SourcePort          int
	DestinationIP       string 
	QueriedName         string
	QueryType           string 
	ResponsePayload     []byte
	ResponseSizeBytes   int
	Timestamp           time.Time
	VariantID           string
	ServiceName         string  
	ProbeType           string  `json:"probe_type"` // "scanner", "attacker", "noise"
	AmplificationFactor float64 
}
