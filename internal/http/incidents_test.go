package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/config"
	"github.com/Network-Detection-and-Response/backend/internal/domain"
	httpapi "github.com/Network-Detection-and-Response/backend/internal/http"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	"github.com/Network-Detection-and-Response/backend/internal/service/incidents"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type incidentMem struct {
	items map[uuid.UUID]domain.Incident
}

func (m *incidentMem) ListIncidents(ctx context.Context, f postgres.IncidentListFilter) ([]domain.Incident, int64, error) {
	var out []domain.Incident
	for _, inc := range m.items {
		if f.Severity != nil && inc.Severity != *f.Severity {
			continue
		}
		if f.Status != nil && inc.Status != *f.Status {
			continue
		}
		out = append(out, inc)
	}
	return out, int64(len(out)), nil
}

func (m *incidentMem) GetIncidentByID(ctx context.Context, id uuid.UUID) (domain.Incident, error) {
	inc, ok := m.items[id]
	if !ok {
		return domain.Incident{}, pgx.ErrNoRows
	}
	return inc, nil
}

func (m *incidentMem) UpdateIncidentStatus(ctx context.Context, id uuid.UUID, status string) (domain.Incident, error) {
	inc, ok := m.items[id]
	if !ok {
		return domain.Incident{}, pgx.ErrNoRows
	}
	inc.Status = status
	m.items[id] = inc
	return inc, nil
}

func incidentsRouter(store *incidentMem) http.Handler {
	cfg := config.Config{
		SensorAPIKey:     "k",
		MaxBodyBytes:     1 << 20,
		MaxFlowsPerBatch: 100,
	}
	return httpapi.NewRouter(httpapi.Dependencies{
		Config:          cfg,
		DB:              dbOK{},
		FlowEnqueuer:    &memQueue{},
		IncidentService: incidents.NewService(store),
	})
}

func TestIncidentsListPaginationValidation(t *testing.T) {
	r := incidentsRouter(&incidentMem{items: map[uuid.UUID]domain.Incident{}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?page=0", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestIncidentsListAndGetAndPatch(t *testing.T) {
	id := uuid.New()
	store := &incidentMem{items: map[uuid.UUID]domain.Incident{
		id: {
			ID: id, CreatedAt: time.Date(2026, 10, 9, 14, 30, 0, 0, time.UTC),
			SrcIP: netip.MustParseAddr("192.168.1.50"), DstIP: netip.MustParseAddr("10.0.0.5"),
			AttackClass: domain.AttackDDoS, Severity: domain.SeverityCritical, Status: domain.StatusOpen,
			MLConfidence: 0.9, AgentVerdict: "ddos", RecommendedAction: "check",
		},
	}}
	r := incidentsRouter(store)

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?severity=CRITICAL&status=OPEN", nil)
	listW := httptest.NewRecorder()
	r.ServeHTTP(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listW.Code, listW.Body.String())
	}
	var listBody map[string]any
	if err := json.Unmarshal(listW.Body.Bytes(), &listBody); err != nil {
		t.Fatal(err)
	}
	data := listBody["data"].(map[string]any)
	if int(data["total"].(float64)) != 1 {
		t.Fatalf("total=%v", data["total"])
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/"+id.String(), nil)
	getW := httptest.NewRecorder()
	r.ServeHTTP(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("get status=%d", getW.Code)
	}

	patchBody := bytes.NewBufferString(`{"status":"ACKNOWLEDGED"}`)
	patchReq := httptest.NewRequest(http.MethodPatch, "/api/v1/incidents/"+id.String(), patchBody)
	patchReq.Header.Set("Content-Type", "application/json")
	patchW := httptest.NewRecorder()
	r.ServeHTTP(patchW, patchReq)
	if patchW.Code != http.StatusOK {
		t.Fatalf("patch status=%d body=%s", patchW.Code, patchW.Body.String())
	}

	bad := bytes.NewBufferString(`{"status":"OPEN"}`)
	badReq := httptest.NewRequest(http.MethodPatch, "/api/v1/incidents/"+id.String(), bad)
	badReq.Header.Set("Content-Type", "application/json")
	badW := httptest.NewRecorder()
	r.ServeHTTP(badW, badReq)
	if badW.Code != http.StatusBadRequest && badW.Code != http.StatusConflict {
		t.Fatalf("invalid transition status=%d", badW.Code)
	}

	missing := httptest.NewRequest(http.MethodGet, "/api/v1/incidents/"+uuid.New().String(), nil)
	missW := httptest.NewRecorder()
	r.ServeHTTP(missW, missing)
	if missW.Code != http.StatusNotFound {
		t.Fatalf("missing status=%d", missW.Code)
	}
}

func TestIncidentsRejectsInvalidFilter(t *testing.T) {
	r := incidentsRouter(&incidentMem{items: map[uuid.UUID]domain.Incident{}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents?severity=NOPE", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", w.Code)
	}
}
