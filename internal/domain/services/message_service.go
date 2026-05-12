package services

import (
	"github.com/hacking-lab/ddos-honeypot/internal/domain/models"
	"time"
)

// ProbeService handles business logic for processing probes
type ProbeService struct{}

// ProcessProbe processes an incoming probe and generates a response
func (ps *ProbeService) ProcessProbe(sourceIP string, port int, protocol string, payload string) *models.ProbeEvent {
	return &models.ProbeEvent{
		ID:        sourceIP + "-" + string(rune(port)),
		SourceIP:  sourceIP,
		Port:      port,
		Protocol:  protocol,
		Payload:   payload,
		Timestamp: time.Now(),
		Response:  "amplified-response", // In real implementation, this would vary by variant
	}
}
