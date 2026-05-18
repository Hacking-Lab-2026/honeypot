package handlers

import "github.com/Hacking-Lab-2026/honeypot/internal/usecases/probe"

// ProbeHandler receives incoming UDP probe requests and orchestrates usecases
type ProbeHandler struct {
	usecase *probe.ProcessProbeUsecase
}

// NewProbeHandler creates a new handler
func NewProbeHandler(usecase *probe.ProcessProbeUsecase) *ProbeHandler {
	return &ProbeHandler{
		usecase: usecase,
	}
}

// Handle processes an incoming probe and returns response
func (h *ProbeHandler) Handle(sourceIP string, port int, protocol string, payload string) (string, error) {
	return h.usecase.Execute(sourceIP, port, protocol, payload)
}
