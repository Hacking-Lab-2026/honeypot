package handlers

import (
	"fmt"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
	expusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/experiment"
	ssdpusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/ssdp"
)

type SSDPHandler struct {
	handleUsecase *ssdpusecase.HandleSSDPRequestUsecase
	assignUsecase *expusecase.AssignVariantUsecase
	logger        ports.Logger
}

func NewSSDPHandler(
	handleUsecase *ssdpusecase.HandleSSDPRequestUsecase,
	assignUsecase *expusecase.AssignVariantUsecase,
	logger ports.Logger,
) *SSDPHandler {
	return &SSDPHandler{
		handleUsecase: handleUsecase,
		assignUsecase: assignUsecase,
		logger:        logger,
	}
}

func (h *SSDPHandler) Handle(sourceIP string, sourcePort int, destinationIP string, payload []byte) ([][]byte, error) {
	config := models.SSDPConfig{ResponseMode: "minimal"}
	variantID := ""

	variant, err := h.assignUsecase.Execute(sourceIP, destinationIP)
	if err != nil {
		h.logger.Info(fmt.Sprintf("variant assignment failed for %s: %v", sourceIP, err))
	} else if variant == nil {
		h.logger.Info(fmt.Sprintf("no variant assigned for %s, using default", sourceIP))
	} else {
		config = variant.GetSSDPConfig()
		variantID = variant.ID
		h.logger.Info(fmt.Sprintf("SSDP variant=%s name=%s ssdp_mode=%q num_services=%d",
			variant.ID, variant.Name, config.ResponseMode, config.NumServices))
	}

	return h.handleUsecase.Execute(sourceIP, sourcePort, destinationIP, payload, config, variantID)
}
