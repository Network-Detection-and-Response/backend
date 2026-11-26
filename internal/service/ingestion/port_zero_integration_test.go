package ingestion_test

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	"github.com/Network-Detection-and-Response/backend/internal/service/ingestion"
	"github.com/google/uuid"
)

func TestIngestionPersistsICMPAndFloodPortZero(t *testing.T) {
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
	svc := ingestion.NewService(store, ingestion.Options{})
	q := ingestion.NewQueue(8, 1, ingestion.DefaultRetryPolicy(), svc, slog.Default())
	defer q.Shutdown(context.Background())

	raw := []byte(`{
  "sensor_id": "port_zero_probe",
  "timestamp": "2026-11-25T14:30:00Z",
  "flows": [
    {
      "src_ip": "192.168.10.1",
      "src_mac": null,
      "dst_ip": "192.168.10.2",
      "dst_mac": null,
      "src_port": 0,
      "dst_port": 0,
      "protocol": "ICMP",
      "duration_ms": 1,
      "total_packets": 2,
      "total_bytes": 128
    },
    {
      "src_ip": "192.168.10.3",
      "src_mac": null,
      "dst_ip": "192.168.10.4",
      "dst_mac": null,
      "src_port": 0,
      "dst_port": 80,
      "protocol": "TCP",
      "duration_ms": 1000,
      "total_packets": 5000,
      "total_bytes": 250000,
      "tcp_flags": {"syn": 5000, "ack": 0, "rst": 0}
    }
  ]
}`)
	job, err := ingestion.DecodeAndValidate(raw, 100)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if job.Flows[0].SrcPort != 0 || job.Flows[1].SrcPort != 0 {
		t.Fatalf("expected port 0 flows, got %+v", job.Flows)
	}
	if !q.TryEnqueue(job) {
		t.Fatal("enqueue failed")
	}

	waitBatch(t, store, ctx, job.BatchID, 2)

	icmp, err := store.GetFlowByID(ctx, job.Flows[0].ID)
	if err != nil {
		t.Fatalf("get icmp: %v", err)
	}
	if icmp.Protocol != "ICMP" || icmp.SrcPort != 0 || icmp.DstPort != 0 {
		t.Fatalf("icmp row=%+v", icmp)
	}

	flood, err := store.GetFlowByID(ctx, job.Flows[1].ID)
	if err != nil {
		t.Fatalf("get flood: %v", err)
	}
	if flood.Protocol != "TCP" || flood.SrcPort != 0 || flood.DstPort != 80 {
		t.Fatalf("flood row=%+v", flood)
	}
	if flood.TCPFlags.SYN != 5000 {
		t.Fatalf("flood syn=%d", flood.TCPFlags.SYN)
	}
}

func waitBatch(t *testing.T, store *postgres.Store, ctx context.Context, batchID uuid.UUID, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, err := store.CountFlowsByBatchID(ctx, batchID)
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		if n == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	n, err := store.CountFlowsByBatchID(ctx, batchID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	t.Fatalf("flows for batch = %d, want %d", n, want)
}
