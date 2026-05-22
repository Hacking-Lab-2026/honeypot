package dns

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/services"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
)

// HandleDNSQueryUsecase orchestrates the full lifecycle of a DNS probe packet:
// rate-limit â†’ parse â†’ build response â†’ persist â†’ log â†’ return bytes.
type HandleDNSQueryUsecase struct {
	dnsService  *services.DNSService
	repository  ports.DNSEventRepository
	logger      ports.Logger
	rateLimiter ports.RateLimiter
	classifier  ports.Classifier
}

// NewHandleDNSQueryUsecase creates a new instance with all required dependencies.
// The optional classifier parameter enables probe-type tagging on saved events.
func NewHandleDNSQueryUsecase(
	dnsService *services.DNSService,
	repository ports.DNSEventRepository,
	logger ports.Logger,
	rateLimiter ports.RateLimiter,
	classifier ...ports.Classifier,
) *HandleDNSQueryUsecase {
	var c ports.Classifier
	if len(classifier) > 0 {
		c = classifier[0]
	}
	return &HandleDNSQueryUsecase{
		dnsService:  dnsService,
		repository:  repository,
		logger:      logger,
		rateLimiter: rateLimiter,
		classifier:  c,
	}
}

// Execute processes a raw DNS query payload and returns the response bytes to send back.
// destinationIP is the honeypot address the probe arrived on; variantID is the A/B arm.
func (u *HandleDNSQueryUsecase) Execute(sourceIP string, sourcePort int, destinationIP string, payload []byte, config models.DNSConfig, variantID string) ([]byte, error) {
	if !u.rateLimiter.Allow(sourceIP, 0) {
		u.logger.Info("DNS query from " + sourceIP + " rate limited")
		return nil, nil
	}

	query, err := ParseQuery(payload)
	if err != nil {
		u.logger.Error(fmt.Sprintf("malformed DNS query from %s: %v", sourceIP, err))
		return nil, err
	}

	response, err := u.dnsService.BuildResponse(query, config)
	if err != nil {
		u.logger.Error(fmt.Sprintf("failed to build DNS response for %s: %v", sourceIP, err))
		return nil, err
	}

	ampFactor := 0.0
	if query.RawSize > 0 {
		ampFactor = float64(len(response.Payload)) / float64(query.RawSize)
	}

	queryTypeStr := queryTypeName(query.Type)
	probeType := ""
	if u.classifier != nil {
		probeType = u.classifier.Classify(sourceIP, queryTypeStr)
	}

	event := &models.DNSEvent{
		ID:                  newEventID(),
		SourceIP:            sourceIP,
		SourcePort:          sourcePort,
		DestinationIP:       destinationIP,
		QueriedName:         query.Name,
		QueryType:           queryTypeStr,
		ResponsePayload:     response.Payload,
		ResponseSizeBytes:   len(response.Payload),
		Timestamp:           time.Now(),
		VariantID:           variantID,
		ServiceName:         "dns",
		ProbeType:           probeType,
		AmplificationFactor: ampFactor,
	}

	if err := u.repository.Save(event); err != nil {
		u.logger.Error(fmt.Sprintf("failed to save DNS event from %s: %v", sourceIP, err))
		return nil, err
	}

	u.logger.Info(fmt.Sprintf("DNS query from %s:%d name=%q type=%s amp=%.1fx variant=%q",
		sourceIP, sourcePort, query.Name, event.QueryType, ampFactor, variantID))

	return response.Payload, nil
}

// queryTypeName returns a human-readable label for a DNS QTYPE value.
func queryTypeName(qtype uint16) string {
	switch qtype {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", qtype)
	}
}

// newEventID generates a random 16-character hex string for event IDs.
func newEventID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck â€” crypto/rand.Read never returns an error on supported platforms
	return hex.EncodeToString(b)
}
