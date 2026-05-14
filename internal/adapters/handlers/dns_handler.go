package handlers

import (
	"github.com/hacking-lab/ddos-honeypot/internal/domain/models"
	dnsusecase "github.com/hacking-lab/ddos-honeypot/internal/usecases/dns"
	expusecase "github.com/hacking-lab/ddos-honeypot/internal/usecases/experiment"
	"github.com/hacking-lab/ddos-honeypot/internal/ports"
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
	handleUsecase      *dnsusecase.HandleDNSQueryUsecase
	assignUsecase      *expusecase.AssignVariantUsecase
	activeExperimentID string // empty string disables A/B assignment
	logger             ports.Logger
}

// NewDNSHandler creates a new handler.
// Set activeExperimentID to "" to run all probes with the default (Minimal) config.
func NewDNSHandler(
	handleUsecase *dnsusecase.HandleDNSQueryUsecase,
	assignUsecase *expusecase.AssignVariantUsecase,
	activeExperimentID string,
	logger ports.Logger,
) *DNSHandler {
	return &DNSHandler{
		handleUsecase:      handleUsecase,
		assignUsecase:      assignUsecase,
		activeExperimentID: activeExperimentID,
		logger:             logger,
	}
}

// Handle resolves the A/B variant config then processes the DNS query.
// destinationIP is the honeypot address the probe arrived on; it is used for destination-mode
// variant assignment and is recorded in the event log.
func (h *DNSHandler) Handle(sourceIP string, sourcePort int, destinationIP string, payload []byte) ([]byte, error) {
	config := defaultDNSConfig
	variantID := ""

	if h.activeExperimentID != "" {
		variant, err := h.assignUsecase.Execute(h.activeExperimentID, sourceIP, destinationIP)
		if err != nil {
			h.logger.Error("variant assignment failed for " + sourceIP + ": " + err.Error() + " — using default config")
		} else {
			config = variant.DNSConfig
			variantID = variant.ID
		}
	}

	return h.handleUsecase.Execute(sourceIP, sourcePort, destinationIP, payload, config, variantID)
}
