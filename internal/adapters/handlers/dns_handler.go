package handlers

import (
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	dnsusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/dns"
	expusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/experiment"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
)

// defaultDNSConfig is used when no experiment is active
var defaultDNSConfig = models.DNSConfig{
	ResponseMode: models.Minimal,
	RealisticTTL: true,
}

type DNSHandler struct {
	handleUsecase *dnsusecase.HandleDNSQueryUsecase
	assignUsecase *expusecase.AssignVariantUsecase
	logger        ports.Logger
}

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


func (h *DNSHandler) Handle(sourceIP string, sourcePort int, destinationIP string, payload []byte) ([]byte, error) {
	config := defaultDNSConfig
	variantID := ""

	variant, err := h.assignUsecase.Execute(sourceIP, destinationIP)
	if err != nil {
	} else {
		config = variant.GetDNSConfig()
		variantID = variant.ID
	}

	return h.handleUsecase.Execute(sourceIP, sourcePort, destinationIP, payload, config, variantID)
}
