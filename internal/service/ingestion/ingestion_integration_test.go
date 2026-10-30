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

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	"github.com/Network-Detection-and-Response/backend/internal/service/ingestion"
)

func TestIngestionPersistsFlowsNodesEdges(t *testing.T) {
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
	svc := ingestion.NewService(store)
	q := ingestion.NewQueue(8, 1, svc, slog.Default())
	defer q.Shutdown(context.Background())

	raw := []byte(`{
  "sensor_id": "core_switch_mirror",
  "timestamp": "2026-10-09T14:30:00Z",
  "flows": [{
    "src_ip": "192.168.1.50",
    "src_mac": null,
    "dst_ip": "10.0.0.5",
    "dst_mac": "AA:BB:CC:DD:EE:FF",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "TCP",
    "duration_ms": 1500,
    "total_packets": 45,
    "total_bytes": 35000
  }]
}`)
	job, err := ingestion.DecodeAndValidate(raw, 100)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !q.TryEnqueue(job) {
		t.Fatal("enqueue failed")
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, err := store.CountFlowsByBatchID(ctx, job.BatchID)
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		if n == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	n, err := store.CountFlowsByBatchID(ctx, job.BatchID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("flows for batch = %d, persist_failures=%d", n, q.PersistFailures())
	}

	nodes, err := store.ListNodes(ctx)
	if err != nil {
		t.Fatalf("nodes: %v", err)
	}
	wantSrc := domain.MakeNodeID(nil, job.Flows[0].SrcIP)
	wantDst := domain.MakeNodeID(job.Flows[0].DstMAC, job.Flows[0].DstIP)
	foundSrc, foundDst := false, false
	for _, node := range nodes {
		if node.ID == wantSrc {
			foundSrc = true
		}
		if node.ID == wantDst {
			foundDst = true
		}
	}
	if !foundSrc || !foundDst {
		t.Fatalf("missing nodes src=%v dst=%v (want %s / %s)", foundSrc, foundDst, wantSrc, wantDst)
	}

	edges, err := store.ListEdges(ctx)
	if err != nil {
		t.Fatalf("edges: %v", err)
	}
	foundEdge := false
	for _, e := range edges {
		if e.SourceNodeID == wantSrc && e.TargetNodeID == wantDst && e.Protocol == "TCP" {
			foundEdge = true
			break
		}
	}
	if !foundEdge {
		t.Fatal("expected edge for accepted batch")
	}
}
