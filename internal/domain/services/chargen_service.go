package services

import (
	"fmt"
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"time"
)

// ChargenService handles business logic for processing CHARGEN (RFC 864) probes
type ChargenService struct{}

// ProcessChargen processes an incoming CHARGEN probe and generates a response
func (cs *ChargenService) ProcessChargen(sourceIP string, port int, protocol string, payload string) *models.ChargenEvent {
	return &models.ChargenEvent{
		ID:        fmt.Sprintf("%s-%d", sourceIP, port),
		SourceIP:  sourceIP,
		Port:      port,
		Protocol:  protocol,
		Payload:   payload,
		Timestamp: time.Now(),
		Response:  "amplified-response", // In real implementation, this would vary by variant
	}
}
