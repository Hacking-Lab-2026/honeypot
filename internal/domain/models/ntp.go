package models

import "time"

type NTPConfig struct {
	ResponseMode string `json:"response_mode"` // minimal or amplified
	NumPeers     int    `json:"num_peers"`     // number of fake peers returned, used in amplified
}

type NTPQuery struct {
	LI                uint8 // leap indicator
	VN                uint8 // version number
	Mode              uint8 // mode (1=client,4=server)
	Stratum           uint8
	Poll              int8
	Precision         int8
	TransmitTimestamp uint64 // client's transmit timestamp (offset 40)
	RawSize           int
}

type NTPResponse struct {
	Payload []byte
}

type NTPEvent struct {
	ID                  string
	SourceIP            string
	SourcePort          int
	DestinationIP       string
	Mode                string
	Stratum             int
	ResponsePayload     []byte
	ResponseSizeBytes   int
	Timestamp           time.Time
	VariantID           string
	ServiceName         string
	ProbeType           string
	AmplificationFactor float64
}
