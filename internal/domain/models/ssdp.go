package models

import "time"

type SSDPConfig struct {
	ResponseMode string `json:"response_mode" yaml:"response_mode"`
	NumServices  int    `json:"num_services" yaml:"num_services"`
}

type SSDPQuery struct {
	Method  string // "M-SEARCH"
	Host    string // "239.255.255.250:1900" typically
	MAN     string // "ssdp:discover"
	MX      string // max response wait time (seconds)
	ST      string // search target
	RawSize int
}

type SSDPResponse struct {
	Packets [][]byte
}

func SingleSSDPPacketResponse(p []byte) SSDPResponse {
	return SSDPResponse{Packets: [][]byte{p}}
}

// returns the sum of all packet payload sizes
func (r SSDPResponse) TotalBytes() int {
	n := 0
	for _, p := range r.Packets {
		n += len(p)
	}
	return n
}

// records a single SSDP request/response interaction
type SSDPEvent struct {
	ID                  string
	SourceIP            string
	SourcePort          int
	DestinationIP       string
	SearchTarget        string // value of ST header from the request
	ResponsePayload     []byte // concatenation of all response packets
	ResponseSizeBytes   int
	ResponsePacketCount int
	Timestamp           time.Time
	VariantID           string
	ServiceName         string
	ProbeType           string
	AmplificationFactor float64
}
