package ingestion_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/agent"
	"github.com/Network-Detection-and-Response/backend/internal/integrations/ml"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	"github.com/Network-Detection-and-Response/backend/internal/service/ingestion"
	"github.com/google/uuid"
)

func TestIngestionMLCreatesIncidentAndSurvivesMLOutage(t *testing.T) {
	if _, err := exec.LookPath("goose"); err != nil {
		t.Skip("goose CLI not installed")
	}

	ctx := context.Background()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://ndr:ndr@localhost:5432/ndr?sslmode=disable"
	}

	pool, err := postgres.Connect(ctx, dbURL)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer pool.Close()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	mig := filepath.Join(root, "migrations")
	cmd := exec.Command("goose", "-dir", mig, "postgres", dbURL, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("goose up: %v\n%s", err, out)
	}

	store := postgres.NewStore(pool)

	var lastFlowID uuid.UUID
	mlOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ml.PredictRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
			http.Error(w, "bad", 400)
			return
		}
		if len(req.Flows) != 1 {
			t.Errorf("flows=%d", len(req.Flows))
		}
		lastFlowID = uuid.MustParse(req.Flows[0].FlowID)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"predictions": []map[string]any{{
				"flow_id": req.Flows[0].FlowID,
				"probabilities": map[string]float64{
					"Normal": 0.10, "PortScan": 0.70, "DDoS": 0.10, "BruteForce": 0.10,
				},
			}},
		})
	}))
	defer mlOK.Close()

	decisionAgent := agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil)
	svc := ingestion.NewService(store, ingestion.Options{
		Predictor:     ml.NewClient(mlOK.URL, 2*time.Second),
		DecisionStore: store,
		Agent:         decisionAgent,
		Log:           slog.Default(),
	})

	raw := []byte(`{
  "sensor_id": "core_switch_mirror",
  "timestamp": "2026-10-09T14:30:00Z",
  "flows": [{
    "src_ip": "192.168.66.10",
    "src_mac": null,
    "dst_ip": "10.0.66.5",
    "dst_mac": null,
    "src_port": 40000,
    "dst_port": 22,
    "protocol": "TCP",
    "duration_ms": 100,
    "total_packets": 20,
    "total_bytes": 2000
  }]
}`)
	job, err := ingestion.DecodeAndValidate(raw, 100)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := svc.ProcessBatch(ctx, job); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	n, err := store.CountFlowsByBatchID(ctx, job.BatchID)
	if err != nil || n != 1 {
		t.Fatalf("flows=%d err=%v", n, err)
	}
	if lastFlowID != job.Flows[0].ID {
		t.Fatalf("ml saw flow %s want %s", lastFlowID, job.Flows[0].ID)
	}

	exists, err := store.HasIncidentForFlowID(ctx, job.Flows[0].ID)
	if err != nil {
		t.Fatalf("has incident: %v", err)
	}
	if !exists {
		t.Fatal("expected incident after successful ML")
	}

	// Re-score same job path via second ProcessBatch would conflict on flow PK.
	// Dedup is covered in unit tests; here verify ML outage keeps telemetry.
	mlDown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer mlDown.Close()

	svcDown := ingestion.NewService(store, ingestion.Options{
		Predictor:     ml.NewClient(mlDown.URL, time.Second),
		DecisionStore: store,
		Agent:         decisionAgent,
		Log:           slog.Default(),
	})
	raw2 := []byte(`{
  "sensor_id": "core_switch_mirror",
  "timestamp": "2026-10-09T14:31:00Z",
  "flows": [{
    "src_ip": "192.168.66.11",
    "src_mac": null,
    "dst_ip": "10.0.66.5",
    "dst_mac": null,
    "src_port": 40001,
    "dst_port": 22,
    "protocol": "TCP",
    "duration_ms": 100,
    "total_packets": 5,
    "total_bytes": 500
  }]
}`)
	job2, err := ingestion.DecodeAndValidate(raw2, 100)
	if err != nil {
		t.Fatalf("validate2: %v", err)
	}
	if err := svcDown.ProcessBatch(ctx, job2); err != nil {
		t.Fatalf("ProcessBatch with ML down must succeed: %v", err)
	}
	n2, err := store.CountFlowsByBatchID(ctx, job2.BatchID)
	if err != nil || n2 != 1 {
		t.Fatalf("flows after ML outage=%d err=%v", n2, err)
	}
	exists2, err := store.HasIncidentForFlowID(ctx, job2.Flows[0].ID)
	if err != nil {
		t.Fatalf("has incident2: %v", err)
	}
	if exists2 {
		t.Fatal("must not fabricate incident when ML is down")
	}
	if svcDown.MLFailures() != 1 {
		t.Fatalf("mlFailures=%d", svcDown.MLFailures())
	}
}
