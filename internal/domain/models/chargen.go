package models

import "time"

// ChargenEvent probe/attack attempt in the honeypot
type ChargenEvent struct {
	ID        string
	SourceIP  string
	Port      int
	Protocol  string
	Payload   string
	Timestamp time.Time
	Response  string
}
