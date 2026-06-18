package handlers

import "github.com/Hacking-Lab-2026/honeypot/internal/usecases/chargen"

type ChargenHandler struct {
	usecase *chargen.HandleChargenRequestUsecase
}

func NewChargenHandler(usecase *chargen.HandleChargenRequestUsecase) *ChargenHandler {
	return &ChargenHandler{
		usecase: usecase,
	}
}

func (h *ChargenHandler) Handle(sourceIP string, port int, protocol string, payload string) (string, error) {
	return h.usecase.Execute(sourceIP, port, protocol, payload)
}
