package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"github.com/Hacking-Lab-2026/honeypot/internal/ports"
	expusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/experiment"
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
	dnsEventRepo     ports.DNSEventRepository
	ntpEventRepo     ports.NTPEventRepository
}

// NewCoordinatorServer creates the HTTP coordinator server.
// The optional dnsEventRepo and ntpEventRepo parameters enable the GET /metrics endpoint.
func NewCoordinatorServer(
	addr string,
	createExperiment *expusecase.CreateExperimentUsecase,
	listExperiments *expusecase.ListExperimentsUsecase,
	getExperiment *expusecase.GetExperimentUsecase,
	updateStatus *expusecase.UpdateStatusUsecase,
	logger ports.Logger,
	dnsEventRepo ports.DNSEventRepository,
	ntpEventRepo ports.NTPEventRepository,
) *CoordinatorServer {
	return &CoordinatorServer{
		addr:             addr,
		createExperiment: createExperiment,
		listExperiments:  listExperiments,
		getExperiment:    getExperiment,
		updateStatus:     updateStatus,
		logger:           logger,
		dnsEventRepo:     dnsEventRepo,
		ntpEventRepo:     ntpEventRepo,
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
//	GET  /metrics                  → metrics
//	GET  /events                   → events (last 100 DNS events)
//	GET  /stats/timeseries         → hourly probe counts over 24 h
//	GET  /stats/query-types        → query type distribution
//	GET  /stats/top-ips            → top 10 source IPs
//	GET  /dashboard                → monitoring dashboard HTML
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

	case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "metrics":
		s.handleMetrics(w, r)

	case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "events":
		s.handleEvents(w, r)

	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "stats" && parts[1] == "timeseries":
		s.handleTimeseries(w, r)

	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "stats" && parts[1] == "query-types":
		s.handleQueryTypes(w, r)

	case r.Method == http.MethodGet && len(parts) == 2 && parts[0] == "stats" && parts[1] == "top-ips":
		s.handleTopIPs(w, r)

	case r.Method == http.MethodGet && len(parts) == 1 && parts[0] == "dashboard":
		s.handleDashboard(w, r)

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
	NTPConfig   models.NTPConfig `json:"ntp_config"`
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
			NTPConfig:   v.NTPConfig,
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

type metricsResponse struct {
	ProbeCounts    map[string]int `json:"probe_counts"`
	Total          int            `json:"total"`
	NTPProbeCounts map[string]int `json:"ntp_probe_counts,omitempty"`
	NTPTotal       int            `json:"ntp_total,omitempty"`
}

func (s *CoordinatorServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	counts := map[string]int{"scanner": 0, "attacker": 0, "noise": 0}
	total := 0
	if s.dnsEventRepo != nil {
		events, err := s.dnsEventRepo.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, ev := range events {
			counts[ev.ProbeType]++
			total++
		}
	}
	ntpCounts := map[string]int{"scanner": 0, "attacker": 0, "noise": 0}
	ntpTotal := 0
	if s.ntpEventRepo != nil {
		events, err := s.ntpEventRepo.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, ev := range events {
			ntpCounts[ev.ProbeType]++
			ntpTotal++
		}
	}
	writeJSON(w, http.StatusOK, metricsResponse{ProbeCounts: counts, Total: total, NTPProbeCounts: ntpCounts, NTPTotal: ntpTotal})
}

// ---- analytics handlers ----

type eventItem struct {
	ID                  string    `json:"id"`
	SourceIP            string    `json:"source_ip"`
	DestinationIP       string    `json:"destination_ip"`
	QueriedName         string    `json:"queried_name"`
	QueryType           string    `json:"query_type"`
	ResponseSizeBytes   int       `json:"response_size_bytes"`
	AmplificationFactor float64   `json:"amplification_factor"`
	VariantID           string    `json:"variant_id"`
	ServiceName         string    `json:"service_name"`
	ProbeType           string    `json:"probe_type"`
	Timestamp           time.Time `json:"timestamp"`
}

type eventsListResponse struct {
	Events []eventItem `json:"events"`
	Total  int         `json:"total"`
}

func (s *CoordinatorServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.dnsEventRepo == nil {
		writeJSON(w, http.StatusOK, eventsListResponse{Events: []eventItem{}, Total: 0})
		return
	}
	all, err := s.dnsEventRepo.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].Timestamp.After(all[j].Timestamp)
	})
	if len(all) > 100 {
		all = all[:100]
	}
	items := make([]eventItem, len(all))
	for i, ev := range all {
		items[i] = eventItem{
			ID:                  ev.ID,
			SourceIP:            ev.SourceIP,
			DestinationIP:       ev.DestinationIP,
			QueriedName:         ev.QueriedName,
			QueryType:           ev.QueryType,
			ResponseSizeBytes:   ev.ResponseSizeBytes,
			AmplificationFactor: ev.AmplificationFactor,
			VariantID:           ev.VariantID,
			ServiceName:         ev.ServiceName,
			ProbeType:           ev.ProbeType,
			Timestamp:           ev.Timestamp,
		}
	}
	writeJSON(w, http.StatusOK, eventsListResponse{Events: items, Total: len(items)})
}

type timeseriesBucket struct {
	Hour     time.Time `json:"hour"`
	Attacker int       `json:"attacker"`
	Scanner  int       `json:"scanner"`
	Noise    int       `json:"noise"`
}

type timeseriesResponse struct {
	Buckets []timeseriesBucket `json:"buckets"`
}

func (s *CoordinatorServer) handleTimeseries(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	startHour := now.Truncate(time.Hour).Add(-23 * time.Hour)
	buckets := make([]timeseriesBucket, 24)
	for i := range buckets {
		buckets[i] = timeseriesBucket{Hour: startHour.Add(time.Duration(i) * time.Hour)}
	}
	if s.dnsEventRepo != nil {
		all, err := s.dnsEventRepo.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, ev := range all {
			h := ev.Timestamp.UTC().Truncate(time.Hour)
			if h.Before(startHour) {
				continue
			}
			idx := int(h.Sub(startHour).Hours())
			if idx < 0 || idx >= 24 {
				continue
			}
			switch ev.ProbeType {
			case "attacker":
				buckets[idx].Attacker++
			case "scanner":
				buckets[idx].Scanner++
			default:
				buckets[idx].Noise++
			}
		}
	}
	writeJSON(w, http.StatusOK, timeseriesResponse{Buckets: buckets})
}

type queryTypesResponse struct {
	QueryTypes map[string]int `json:"query_types"`
}

func (s *CoordinatorServer) handleQueryTypes(w http.ResponseWriter, r *http.Request) {
	counts := map[string]int{}
	if s.dnsEventRepo != nil {
		all, err := s.dnsEventRepo.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, ev := range all {
			counts[ev.QueryType]++
		}
	}
	writeJSON(w, http.StatusOK, queryTypesResponse{QueryTypes: counts})
}

type ipStat struct {
	IP        string `json:"ip"`
	Count     int    `json:"count"`
	ProbeType string `json:"probe_type"`
}

type topIPsResponse struct {
	TopIPs []ipStat `json:"top_ips"`
}

func (s *CoordinatorServer) handleTopIPs(w http.ResponseWriter, r *http.Request) {
	ipCounts := map[string]int{}
	ipProbeTypes := map[string]map[string]int{}
	if s.dnsEventRepo != nil {
		all, err := s.dnsEventRepo.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		for _, ev := range all {
			ipCounts[ev.SourceIP]++
			if ipProbeTypes[ev.SourceIP] == nil {
				ipProbeTypes[ev.SourceIP] = map[string]int{}
			}
			ipProbeTypes[ev.SourceIP][ev.ProbeType]++
		}
	}
	entries := make([]ipStat, 0, len(ipCounts))
	for ip, count := range ipCounts {
		best, bestCnt := "noise", 0
		for pt, cnt := range ipProbeTypes[ip] {
			if cnt > bestCnt {
				bestCnt = cnt
				best = pt
			}
		}
		entries = append(entries, ipStat{IP: ip, Count: count, ProbeType: best})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})
	if len(entries) > 10 {
		entries = entries[:10]
	}
	writeJSON(w, http.StatusOK, topIPsResponse{TopIPs: entries})
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
