package ssdp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/services"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
)

// orchestrates SSDP request processing
type HandleSSDPRequestUsecase struct {
	ssdpService *services.SSDPService
	repository  ports.SSDPEventRepository
	logger      ports.Logger
	rateLimiter ports.RateLimiter
	classifier  ports.Classifier // may be nil
}

func NewHandleSSDPRequestUsecase(
	ssdpService *services.SSDPService,
	repository ports.SSDPEventRepository,
	logger ports.Logger,
	rateLimiter ports.RateLimiter,
	classifier ports.Classifier,
) *HandleSSDPRequestUsecase {
	return &HandleSSDPRequestUsecase{
		ssdpService: ssdpService,
		repository:  repository,
		logger:      logger,
		rateLimiter: rateLimiter,
		classifier:  classifier,
	}
}

// handles a raw SSDP payload and returns the response packets (if any)
func (u *HandleSSDPRequestUsecase) Execute(
	sourceIP string,
	sourcePort int,
	destinationIP string,
	payload []byte,
	cfg models.SSDPConfig,
	variantID string,
) ([][]byte, error) {
	query, err := ParseSSDPRequest(payload)
	if err != nil {
		u.logger.Info(fmt.Sprintf("non-SSDP packet from %s: %v", sourceIP, err))
		return nil, nil
	}

	if !IsAmplificationProbe(query) {
		u.logger.Info(fmt.Sprintf("non-discovery SSDP from %s, ST=%q, dropped", sourceIP, query.ST))
		return nil, nil
	}

	response, err := u.ssdpService.BuildResponse(query, cfg, destinationIP)
	if err != nil {
		u.logger.Error(fmt.Sprintf("failed to build SSDP response for %s: %v", sourceIP, err))
		return nil, err
	}

	if len(response.Packets) == 0 {
		return nil, nil
	}

	// Per-packet rate limiting (matches NTP pattern)
	sentPackets := make([][]byte, 0, len(response.Packets))
	sentBytes := 0
	for _, pkt := range response.Packets {
		if !u.rateLimiter.Allow(sourceIP, len(pkt)) {
			u.logger.Info(fmt.Sprintf(
				"SSDP response to %s rate limited: sent %d of %d packets",
				sourceIP, len(sentPackets), len(response.Packets),
			))
			break
		}
		sentPackets = append(sentPackets, pkt)
		sentBytes += len(pkt)
	}

	amp := 0.0
	if query.RawSize > 0 {
		amp = float64(sentBytes) / float64(query.RawSize)
	}

	probeType := ""
	if u.classifier != nil {
		probeType = u.classifier.Classify(sourceIP, "SSDP")
	}

	concatenated := make([]byte, 0, sentBytes)
	for _, pkt := range sentPackets {
		concatenated = append(concatenated, pkt...)
	}

	event := &models.SSDPEvent{
		ID:                  newSSDPEventID(),
		SourceIP:            sourceIP,
		SourcePort:          sourcePort,
		DestinationIP:       destinationIP,
		SearchTarget:        query.ST,
		ResponsePayload:     concatenated,
		ResponseSizeBytes:   sentBytes,
		ResponsePacketCount: len(sentPackets),
		Timestamp:           time.Now(),
		VariantID:           variantID,
		ServiceName:         "ssdp",
		ProbeType:           probeType,
		AmplificationFactor: amp,
	}

	if err := u.repository.Save(event); err != nil {
		u.logger.Error(fmt.Sprintf("failed to save SSDP event from %s: %v", sourceIP, err))
	}

	u.logger.Info(fmt.Sprintf(
		"SSDP M-SEARCH from %s:%d ST=%q packets=%d bytes=%d amp=%.1fx variant=%q",
		sourceIP, sourcePort, query.ST, len(sentPackets), sentBytes, amp, variantID,
	))

	return sentPackets, nil
}

func newSSDPEventID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
