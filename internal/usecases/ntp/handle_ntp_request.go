package ntp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/services"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
)

// orchestrates NTP request processing
type HandleNTPRequestUsecase struct {
	ntpService  *services.NTPService
	repository  ports.NTPEventRepository
	logger      ports.Logger
	rateLimiter ports.RateLimiter
	classifier  ports.Classifier
}

func NewHandleNTPRequestUsecase(
	ntpService *services.NTPService,
	repository ports.NTPEventRepository,
	logger ports.Logger,
	rateLimiter ports.RateLimiter,
	classifier ports.Classifier,
) *HandleNTPRequestUsecase {
	return &HandleNTPRequestUsecase{
		ntpService:  ntpService,
		repository:  repository,
		logger:      logger,
		rateLimiter: rateLimiter,
		classifier:  classifier,
	}
}

// handles a raw NTP payload and returns the response packets (if any)
// A nil/empty return means no response should be sent
func (u *HandleNTPRequestUsecase) Execute(
	sourceIP string,
	sourcePort int,
	destinationIP string,
	payload []byte,
	cfg models.NTPConfig,
	variantID string,
) ([][]byte, error) {
	query, err := ParseNTPRequest(payload)
	if err != nil {
		u.logger.Error(fmt.Sprintf("malformed NTP request from %s: %v", sourceIP, err))
		return nil, err
	}

	response, err := u.ntpService.BuildResponse(query, cfg)
	if err != nil {
		u.logger.Error(fmt.Sprintf("failed to build NTP response for %s: %v", sourceIP, err))
		return nil, err
	}

	// No response for unsupported modes.
	if len(response.Packets) == 0 {
		u.logger.Info(fmt.Sprintf("NTP mode %d from %s: no response configured", query.Mode, sourceIP))
		return nil, nil
	}

	// Rate-limit each packet independently. If the bucket runs out mid-response,
	// send what we can and drop the rest. This is the right semantics because
	// each packet contributes to bandwidth toward the (possibly spoofed) victim.
	sentPackets := make([][]byte, 0, len(response.Packets))
	sentBytes := 0
	for _, pkt := range response.Packets {
		if !u.rateLimiter.Allow(sourceIP, len(pkt)) {
			u.logger.Info(fmt.Sprintf(
				"NTP response to %s rate limited: sent %d of %d packets",
				sourceIP, len(sentPackets), len(response.Packets),
			))
			break
		}
		sentPackets = append(sentPackets, pkt)
		sentBytes += len(pkt)
	}

	// Compute amplification based on what we actually sent
	amp := 0.0
	if query.RawSize > 0 {
		amp = float64(sentBytes) / float64(query.RawSize)
	}

	probeType := ""
	if u.classifier != nil {
		probeType = u.classifier.Classify(sourceIP, "NTP")
	}

	// Concatenate sent packets for the event record. (Storing each separately
	// would be more faithful but bloats the record; concatenation preserves the
	// total volume which is what matters for analysis.)
	concatenated := make([]byte, 0, sentBytes)
	for _, pkt := range sentPackets {
		concatenated = append(concatenated, pkt...)
	}

	event := &models.NTPEvent{
		ID:                  newEventID(),
		SourceIP:            sourceIP,
		SourcePort:          sourcePort,
		DestinationIP:       destinationIP,
		Mode:                fmt.Sprintf("%d", query.Mode),
		Stratum:             int(query.Stratum),
		ResponsePayload:     concatenated,
		ResponseSizeBytes:   sentBytes,
		ResponsePacketCount: len(sentPackets),
		Timestamp:           time.Now(),
		VariantID:           variantID,
		ServiceName:         "ntp",
		ProbeType:           probeType,
		AmplificationFactor: amp,
	}

	if err := u.repository.Save(event); err != nil {
		u.logger.Error(fmt.Sprintf("failed to save NTP event from %s: %v", sourceIP, err))
		// Continue, we still want to send what we computed even if persistence failed
	}

	u.logger.Info(fmt.Sprintf(
		"NTP request from %s:%d mode=%d packets=%d bytes=%d amp=%.1fx variant=%q",
		sourceIP, sourcePort, query.Mode, len(sentPackets), sentBytes, amp, variantID,
	))

	return sentPackets, nil
}

func newEventID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
