package models

// NTPConfig holds the honeypot behaviour settings for the NTP protocol.
// ResponseMode controls whether the honeypot returns a minimal or amplified response.
// NumPeers sets how many fake peers are included in an amplified monlist reply.
// RealisticPadding controls whether the peer entries contain realistic-looking
// data or simple repeated bytes.
type NTPConfig struct {
	ResponseMode     string `json:"response_mode"`    // "minimal" or "amplified"
	NumPeers         int    `json:"num_peers"`         // number of fake peers returned, used in amplified mode
	RealisticPadding bool   `json:"realistic_padding"` // realistic peer data vs padding bytes
}
