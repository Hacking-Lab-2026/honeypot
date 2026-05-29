package handlers

import (
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	dnsusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/dns"
	expusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/experiment"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
)

// defaultDNSConfig is used when no experiment is active or variant assignment fails.
var defaultDNSConfig = models.DNSConfig{
	ResponseMode: models.Minimal,
	RealisticTTL: true,
}

// DNSHandler bridges the DNS UDP server to the HandleDNSQueryUsecase.
// Before invoking the DNS usecase it calls AssignVariantUsecase to select the per-source
// DNSConfig, enabling live A/B testing down to the individual packet.
type DNSHandler struct {
	handleUsecase *dnsusecase.HandleDNSQueryUsecase
	assignUsecase *expusecase.AssignVariantUsecase
	logger        ports.Logger
}

// NewDNSHandler creates a new handler.
func NewDNSHandler(
	handleUsecase *dnsusecase.HandleDNSQueryUsecase,
	assignUsecase *expusecase.AssignVariantUsecase,
	logger ports.Logger,
) *DNSHandler {
	return &DNSHandler{
		handleUsecase: handleUsecase,
		assignUsecase: assignUsecase,
		logger:        logger,
	}
}

// Handle resolves the A/B variant config then processes the DNS query.
// If no experiment is active, falls back to the default minimal config.
func (h *DNSHandler) Handle(sourceIP string, sourcePort int, destinationIP string, payload []byte) ([]byte, error) {
	config := defaultDNSConfig
	variantID := ""

	variant, err := h.assignUsecase.Execute(sourceIP, destinationIP)
	if err != nil {
		// No active experiment or assignment failed â€” use safe default silently.
	} else {
		config = variant.GetDNSConfig()
		variantID = variant.ID
		// NTP handler will use: ntpConfig := variant.GetNTPConfig()
	}

	return h.handleUsecase.Execute(sourceIP, sourcePort, destinationIP, payload, config, variantID)
}
