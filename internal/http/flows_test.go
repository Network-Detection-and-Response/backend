package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Network-Detection-and-Response/backend/internal/config"
	httpapi "github.com/Network-Detection-and-Response/backend/internal/http"
	"github.com/Network-Detection-and-Response/backend/internal/service/ingestion"
	"github.com/google/uuid"
)

type memQueue struct {
	mu       sync.Mutex
	full     bool
	accepted int
}

func (m *memQueue) TryEnqueue(job ingestion.BatchJob) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.full {
		return false
	}
	m.accepted++
	return true
}

type dbOK struct{}

func (dbOK) Ping(ctx context.Context) error { return nil }

func testRouter(t *testing.T, q *memQueue, maxBody int64, maxFlows int) http.Handler {
	t.Helper()
	cfg := config.Config{
		SensorAPIKey:       "test-sensor-key",
		MaxBodyBytes:       maxBody,
		MaxFlowsPerBatch:   maxFlows,
		CORSAllowedOrigins: []string{"http://localhost:5173"},
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.MaxFlowsPerBatch <= 0 {
		cfg.MaxFlowsPerBatch = 500
	}
	return httpapi.NewRouter(httpapi.Dependencies{
		Config:       cfg,
		FlowEnqueuer: q,
		DB:           dbOK{},
	})
}

func sampleBody() string {
	return `{
  "sensor_id": "core_switch_mirror",
  "timestamp": "2026-10-09T14:30:00Z",
  "flows": [{
    "src_ip": "192.168.1.50",
    "src_mac": "00:1A:2B:3C:4D:5E",
    "dst_ip": "10.0.0.5",
    "dst_mac": null,
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "TCP",
    "duration_ms": 1500,
    "total_packets": 45,
    "total_bytes": 35000,
    "tcp_flags": {"syn": 1, "ack": 40, "rst": 0}
  }]
}`
}

func TestFlowsAcceptValid(t *testing.T) {
	q := &memQueue{}
	r := testRouter(t, q, 1<<20, 500)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows", strings.NewReader(sampleBody()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sensor-API-Key", "test-sensor-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var envelope struct {
		Data struct {
			BatchID       string `json:"batch_id"`
			AcceptedFlows int    `json:"accepted_flows"`
			Status        string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("json: %v", err)
	}
	if _, err := uuid.Parse(envelope.Data.BatchID); err != nil {
		t.Fatalf("batch_id: %v", err)
	}
	if envelope.Data.AcceptedFlows != 1 || envelope.Data.Status != "accepted" {
		t.Fatalf("unexpected data: %+v", envelope.Data)
	}
	if q.accepted != 1 {
		t.Fatalf("enqueued=%d", q.accepted)
	}
}

func TestFlowsRejectsMissingKey(t *testing.T) {
	r := testRouter(t, &memQueue{}, 1<<20, 500)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows", strings.NewReader(sampleBody()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestFlowsRejectsInvalidKey(t *testing.T) {
	r := testRouter(t, &memQueue{}, 1<<20, 500)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows", strings.NewReader(sampleBody()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sensor-API-Key", "wrong")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestFlowsRejectsInvalidPayload(t *testing.T) {
	r := testRouter(t, &memQueue{}, 1<<20, 500)
	body := `{"sensor_id":"s","timestamp":"2026-10-09T14:30:00Z","flows":[]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sensor-API-Key", "test-sensor-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestFlowsQueueFull(t *testing.T) {
	q := &memQueue{full: true}
	r := testRouter(t, q, 1<<20, 500)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows", strings.NewReader(sampleBody()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sensor-API-Key", "test-sensor-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestFlowsOversizedBody(t *testing.T) {
	r := testRouter(t, &memQueue{}, 64, 500)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows", bytes.NewReader(bytes.Repeat([]byte("a"), 200)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sensor-API-Key", "test-sensor-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s want 413", w.Code, w.Body.String())
	}
}

func TestFlowsTooManyFlows(t *testing.T) {
	r := testRouter(t, &memQueue{}, 1<<20, 1)
	body := `{
  "sensor_id":"s1","timestamp":"2026-10-09T14:30:00Z","flows":[
    {"src_ip":"1.1.1.1","dst_ip":"2.2.2.2","src_port":1,"dst_port":2,"protocol":"UDP","duration_ms":0,"total_packets":1,"total_bytes":1},
    {"src_ip":"1.1.1.1","dst_ip":"2.2.2.2","src_port":3,"dst_port":4,"protocol":"UDP","duration_ms":0,"total_packets":1,"total_bytes":1}
  ]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sensor-API-Key", "test-sensor-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
