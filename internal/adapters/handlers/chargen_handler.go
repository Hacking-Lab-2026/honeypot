package handlers

import "github.com/Hacking-Lab-2026/honeypot/internal/usecases/chargen"

// ChargenHandler receives incoming UDP CHARGEN probe requests and orchestrates usecases
type ChargenHandler struct {
	usecase *chargen.HandleChargenRequestUsecase
}

// NewChargenHandler creates a new handler
func NewChargenHandler(usecase *chargen.HandleChargenRequestUsecase) *ChargenHandler {
	return &ChargenHandler{
		usecase: usecase,
	}
}

// Handle processes an incoming CHARGEN probe and returns response
func (h *ChargenHandler) Handle(sourceIP string, port int, protocol string, payload string) (string, error) {
	return h.usecase.Execute(sourceIP, port, protocol, payload)
}
