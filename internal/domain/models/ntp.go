package models

import "time"

type NTPConfig struct {
	ResponseMode string `json:"response_mode"` // "minimal" or "amplified"
	NumPeers     int    `json:"num_peers"`     // total fake peers across all monlist packets (amplified mode)
}

// NTPQuery is the parsed incoming NTP request.
type NTPQuery struct {
	LI                uint8 // leap indicator
	VN                uint8 // version number
	Mode              uint8 // 3=client, 6=control, 7=private/monlist
	Stratum           uint8
	Poll              int8
	Precision         int8
	TransmitTimestamp uint64 // client's transmit timestamp (offset 40)
	RawSize           int
	ReqCode           uint8 // request code (for mode 7 private messages)
}
type NTPResponse struct {
	Packets [][]byte
}

// SinglePacketResponse is a convenience for the common single-packet case.
func SinglePacketResponse(p []byte) NTPResponse {
	return NTPResponse{Packets: [][]byte{p}}
}

// TotalBytes returns the sum of all packet payload sizes.
func (r NTPResponse) TotalBytes() int {
	n := 0
	for _, p := range r.Packets {
		n += len(p)
	}
	return n
}

// NTPEvent records a single NTP request/response interaction.
type NTPEvent struct {
	ID                  string
	SourceIP            string
	SourcePort          int
	DestinationIP       string
	Mode                string
	Stratum             int
	ResponsePayload     []byte // concatenation of all response packets (for the record)
	ResponseSizeBytes   int
	ResponsePacketCount int
	Timestamp           time.Time
	VariantID           string
	ServiceName         string
	ProbeType           string
	AmplificationFactor float64
}
