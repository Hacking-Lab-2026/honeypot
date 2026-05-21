package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/hacking-lab/ddos-honeypot/internal/domain/models"
	"github.com/hacking-lab/ddos-honeypot/internal/ports"
	expusecase "github.com/hacking-lab/ddos-honeypot/internal/usecases/experiment"
)

// CoordinatorServer exposes the experiment management HTTP API.
// It uses stdlib net/http only — no external router.
type CoordinatorServer struct {
	addr             string
	createExperiment *expusecase.CreateExperimentUsecase
	listExperiments  *expusecase.ListExperimentsUsecase
	getExperiment    *expusecase.GetExperimentUsecase
	updateStatus     *expusecase.UpdateStatusUsecase
	logger           ports.Logger
}

// NewCoordinatorServer creates the HTTP coordinator server.
func NewCoordinatorServer(
	addr string,
	createExperiment *expusecase.CreateExperimentUsecase,
	listExperiments *expusecase.ListExperimentsUsecase,
	getExperiment *expusecase.GetExperimentUsecase,
	updateStatus *expusecase.UpdateStatusUsecase,
	logger ports.Logger,
) *CoordinatorServer {
	return &CoordinatorServer{
		addr:             addr,
		createExperiment: createExperiment,
		listExperiments:  listExperiments,
		getExperiment:    getExperiment,
		updateStatus:     updateStatus,
		logger:           logger,
	}
}

// Start starts the HTTP server and blocks until ctx is cancelled.
func (s *CoordinatorServer) Start(ctx context.Context) error {
	s.logger.Info("Starting coordinator HTTP server on " + s.addr)
	srv := &http.Server{
		Addr:    s.addr,
		Handler: s,
	}

	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background()) //nolint:errcheck
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// ServeHTTP routes requests to the appropriate handler.
//
//	POST /experiments              → createExperiment
//	GET  /experiments              → listExperiments
//	GET  /experiments/{id}         → getExperiment
//	POST /experiments/{id}/start   → startExperiment
//	POST /experiments/{id}/stop    → stopExperiment
func (s *CoordinatorServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")

	switch {
	case r.Method == http.MethodPost && len(parts) == 1 && parts[0] == "experiments":
		s.handleCreateExperiment(w, r)

	case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "experiments":
		s.handleListExperiments(w, r)

	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "experiments":
		s.handleGetExperiment(w, r, parts[1])

	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "experiments" && parts[2] == "start":
		s.handleUpdateStatus(w, r, parts[1], models.StatusActive)

	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "experiments" && parts[2] == "stop":
		s.handleUpdateStatus(w, r, parts[1], models.StatusStopped)

	default:
		http.NotFound(w, r)
	}
}

// ---- request/response types ----

type createVariantRequest struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Weight      float64          `json:"weight"`
	AssignedIPs []string         `json:"assigned_ips"`
	DNSConfig   models.DNSConfig `json:"dns_config"`
}

type createExperimentRequest struct {
	Name           string                 `json:"name"`
	Description    string                 `json:"description"`
	AssignmentMode string                 `json:"assignment_mode"`
	Variants       []createVariantRequest `json:"variants"`
}

// ---- handlers ----

func (s *CoordinatorServer) handleCreateExperiment(w http.ResponseWriter, r *http.Request) {
	var req createExperimentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	variantInputs := make([]expusecase.CreateVariantInput, len(req.Variants))
	for i, v := range req.Variants {
		variantInputs[i] = expusecase.CreateVariantInput{
			Name:        v.Name,
			Description: v.Description,
			Weight:      v.Weight,
			AssignedIPs: v.AssignedIPs,
			DNSConfig:   v.DNSConfig,
		}
	}

	exp, err := s.createExperiment.Execute(expusecase.CreateExperimentInput{
		Name:           req.Name,
		Description:    req.Description,
		AssignmentMode: models.AssignmentMode(req.AssignmentMode),
		Variants:       variantInputs,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, exp)
}

func (s *CoordinatorServer) handleListExperiments(w http.ResponseWriter, r *http.Request) {
	exps, err := s.listExperiments.Execute()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, exps)
}

func (s *CoordinatorServer) handleGetExperiment(w http.ResponseWriter, r *http.Request, id string) {
	details, err := s.getExperiment.Execute(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, details)
}

func (s *CoordinatorServer) handleUpdateStatus(w http.ResponseWriter, r *http.Request, id string, status models.ExperimentStatus) {
	exp, err := s.updateStatus.Execute(id, status)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, exp)
}

// ---- helpers ----

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}
