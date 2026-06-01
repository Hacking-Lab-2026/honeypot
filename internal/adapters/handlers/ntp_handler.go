package handlers

import (
	"fmt"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
	expusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/experiment"
	ntpusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/ntp"
)

type NTPHandler struct {
	handleUsecase *ntpusecase.HandleNTPRequestUsecase
	assignUsecase *expusecase.AssignVariantUsecase
	logger        ports.Logger
}

func NewNTPHandler(
	handleUsecase *ntpusecase.HandleNTPRequestUsecase,
	assignUsecase *expusecase.AssignVariantUsecase,
	logger ports.Logger,
) *NTPHandler {
	return &NTPHandler{
		handleUsecase: handleUsecase,
		assignUsecase: assignUsecase,
		logger:        logger,
	}
}

func (h *NTPHandler) Handle(sourceIP string, sourcePort int, destinationIP string, payload []byte) ([][]byte, error) {
	// default: minimal monlist (non-amplifying)
	config := models.NTPConfig{ResponseMode: "minimal"}
	variantID := ""

	variant, err := h.assignUsecase.Execute(sourceIP, destinationIP)
	if err != nil {
		h.logger.Info(fmt.Sprintf("variant assignment failed for %s: %v", sourceIP, err))
	} else if variant == nil {
		h.logger.Info(fmt.Sprintf("no variant assigned for %s, using default", sourceIP))
	} else {
		config = variant.GetNTPConfig()
		variantID = variant.ID
	}

	return h.handleUsecase.Execute(sourceIP, sourcePort, destinationIP, payload, config, variantID)
}
