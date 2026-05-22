package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/api"
	"github.com/Hacking-Lab-2026/honeypot/internal/adapters/persistence"
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/models"
	"github.com/Hacking-Lab-2026/honeypot/internal/domain/services"
	expusecase "github.com/Hacking-Lab-2026/honeypot/internal/usecases/experiment"
)

type testLogger struct{}

func (l *testLogger) Info(_ string)  {}
func (l *testLogger) Error(_ string) {}

// newTestServer wires a real CoordinatorServer backed by in-memory repos for HTTP testing.
func newTestServer(t *testing.T) *api.CoordinatorServer {
	t.Helper()
	logger := &testLogger{}
	experimentRepo := persistence.NewExperimentInMemoryRepository()
	assignmentRepo := persistence.NewAssignmentInMemoryRepository()
	experimentService := &services.ExperimentService{}

	return api.NewCoordinatorServer(
		":0",
		expusecase.NewCreateExperimentUsecase(experimentService, experimentRepo, logger),
		expusecase.NewListExperimentsUsecase(experimentRepo),
		expusecase.NewGetExperimentUsecase(experimentRepo, assignmentRepo),
		expusecase.NewUpdateStatusUsecase(experimentRepo, logger),
		logger,
	)
}

func createExperimentBody(name string) []byte {
	body, _ := json.Marshal(map[string]interface{}{
		"name":        name,
		"description": "test",
		"variants": []map[string]interface{}{
			{"name": "Control", "weight": 0.5, "dns_config": map[string]interface{}{"response_mode": "minimal", "realistic_ttl": true}},
			{"name": "Treatment", "weight": 0.5, "dns_config": map[string]interface{}{"response_mode": "amplified", "realistic_ttl": false}},
		},
	})
	return body
}

func TestCoordinator_PostExperiments_Created(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/experiments", bytes.NewReader(createExperimentBody("My Test")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var result models.Experiment
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if result.ID == "" {
		t.Error("returned experiment must have an ID")
	}
	if result.Name != "My Test" {
		t.Errorf("Name = %q, want %q", result.Name, "My Test")
	}
	if result.Status != models.StatusStopped {
		t.Errorf("Status = %q, want %q", result.Status, models.StatusStopped)
	}
}

func TestCoordinator_PostExperiments_BadWeights_BadRequest(t *testing.T) {
	srv := newTestServer(t)

	body, _ := json.Marshal(map[string]interface{}{
		"name": "Bad",
		"variants": []map[string]interface{}{
			{"name": "A", "weight": 0.3, "dns_config": map[string]interface{}{"response_mode": "minimal"}},
			{"name": "B", "weight": 0.3, "dns_config": map[string]interface{}{"response_mode": "amplified"}},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/experiments", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCoordinator_GetExperimentByID(t *testing.T) {
	srv := newTestServer(t)

	// Create an experiment first
	req := httptest.NewRequest(http.MethodPost, "/experiments", bytes.NewReader(createExperimentBody("Detail Test")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create failed: %d %s", w.Code, w.Body.String())
	}

	var created models.Experiment
	json.Unmarshal(w.Body.Bytes(), &created)

	// Now GET it
	req2 := httptest.NewRequest(http.MethodGet, "/experiments/"+created.ID, nil)
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w2.Code, w2.Body.String())
	}

	var detail expusecase.ExperimentDetails
	if err := json.Unmarshal(w2.Body.Bytes(), &detail); err != nil {
		t.Fatalf("failed to parse detail response: %v", err)
	}
	if detail.Experiment == nil {
		t.Fatal("detail.Experiment must not be nil")
	}
	if detail.Experiment.ID != created.ID {
		t.Errorf("ID = %q, want %q", detail.Experiment.ID, created.ID)
	}
	if len(detail.Variants) != 2 {
		t.Errorf("Variants count = %d, want 2", len(detail.Variants))
	}
	if detail.Stats.TotalAssignments != 0 {
		t.Errorf("TotalAssignments = %d, want 0 (no probes yet)", detail.Stats.TotalAssignments)
	}
}

func TestCoordinator_GetExperimentByID_NotFound(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/experiments/does-not-exist", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestCoordinator_ListExperiments(t *testing.T) {
	srv := newTestServer(t)

	for _, name := range []string{"Exp1", "Exp2"} {
		req := httptest.NewRequest(http.MethodPost, "/experiments", bytes.NewReader(createExperimentBody(name)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("create %q failed: %d", name, w.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/experiments", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", w.Code)
	}

	var exps []*models.Experiment
	if err := json.Unmarshal(w.Body.Bytes(), &exps); err != nil {
		t.Fatalf("failed to parse list response: %v", err)
	}
	if len(exps) != 2 {
		t.Errorf("list count = %d, want 2", len(exps))
	}
}

func TestCoordinator_StartStop(t *testing.T) {
	srv := newTestServer(t)

	// Create
	req := httptest.NewRequest(http.MethodPost, "/experiments", bytes.NewReader(createExperimentBody("LifecycleTest")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var created models.Experiment
	json.Unmarshal(w.Body.Bytes(), &created)

	// Start
	req2 := httptest.NewRequest(http.MethodPost, "/experiments/"+created.ID+"/start", nil)
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("start status = %d, want 200", w2.Code)
	}
	var startedExp models.Experiment
	json.Unmarshal(w2.Body.Bytes(), &startedExp)
	if startedExp.Status != models.StatusActive {
		t.Errorf("after start, Status = %q, want %q", startedExp.Status, models.StatusActive)
	}

	// Stop
	req3 := httptest.NewRequest(http.MethodPost, "/experiments/"+created.ID+"/stop", nil)
	w3 := httptest.NewRecorder()
	srv.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("stop status = %d, want 200", w3.Code)
	}
	var stoppedExp models.Experiment
	json.Unmarshal(w3.Body.Bytes(), &stoppedExp)
	if stoppedExp.Status != models.StatusStopped {
		t.Errorf("after stop, Status = %q, want %q", stoppedExp.Status, models.StatusStopped)
	}
}

func TestCoordinator_UnknownRoute_NotFound(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}
