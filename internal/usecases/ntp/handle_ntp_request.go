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

// HandleNTPRequestUsecase orchestrates NTP request processing.
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
	classifier ...ports.Classifier,
) *HandleNTPRequestUsecase {
	var c ports.Classifier
	if len(classifier) > 0 {
		c = classifier[0]
	}
	return &HandleNTPRequestUsecase{
		ntpService:  ntpService,
		repository:  repository,
		logger:      logger,
		rateLimiter: rateLimiter,
		classifier:  c,
	}
}

// Execute handles a raw NTP payload and returns the response bytes.
func (u *HandleNTPRequestUsecase) Execute(sourceIP string, sourcePort int, destinationIP string, payload []byte, cfg models.NTPConfig, variantID string) ([]byte, error) {
	if !u.rateLimiter.Allow(sourceIP, 0) {
		u.logger.Info("NTP request from " + sourceIP + " rate limited")
		return nil, nil
	}

	query, err := ParseNTPRequest(payload)
	if err != nil {
		u.logger.Error(fmt.Sprintf("malformed NTP request from %s: %v", sourceIP, err))
		return nil, err
	}

	response, err := u.ntpService.BuildResponse(query)
	if err != nil {
		u.logger.Error(fmt.Sprintf("failed to build NTP response for %s: %v", sourceIP, err))
		return nil, err
	}

	amp := 0.0
	if query.RawSize > 0 {
		amp = float64(len(response.Payload)) / float64(query.RawSize)
	}

	probeType := ""
	if u.classifier != nil {
		probeType = u.classifier.Classify(sourceIP, "NTP")
	}

	event := &models.NTPEvent{
		ID:                  newEventID(),
		SourceIP:            sourceIP,
		SourcePort:          sourcePort,
		DestinationIP:       destinationIP,
		Mode:                fmt.Sprintf("%d", query.Mode),
		Stratum:             int(query.Stratum),
		ResponsePayload:     response.Payload,
		ResponseSizeBytes:   len(response.Payload),
		Timestamp:           time.Now(),
		VariantID:           variantID,
		ServiceName:         "ntp",
		ProbeType:           probeType,
		AmplificationFactor: amp,
	}

	if err := u.repository.Save(event); err != nil {
		u.logger.Error(fmt.Sprintf("failed to save NTP event from %s: %v", sourceIP, err))
		return nil, err
	}

	u.logger.Info(fmt.Sprintf("NTP request from %s:%d mode=%d stratum=%d amp=%.1fx variant=%q",
		sourceIP, sourcePort, query.Mode, query.Stratum, amp, variantID))

	return response.Payload, nil
}

func newEventID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
