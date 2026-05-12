package models

import "time"

// ProbeEvent represents a DDoS probe/attack attempt in the honeypot
type ProbeEvent struct {
	ID        string
	SourceIP  string
	Port      int
	Protocol  string
	Payload   string
	Timestamp time.Time
	Response  string
}
