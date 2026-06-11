package models

import "time"

// ChargenEvent represents a CHARGEN (RFC 864) probe/attack attempt in the honeypot
type ChargenEvent struct {
	ID        string
	SourceIP  string
	Port      int
	Protocol  string
	Payload   string
	Timestamp time.Time
	Response  string
}
