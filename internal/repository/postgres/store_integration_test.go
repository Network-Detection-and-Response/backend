package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		url = "postgres://ndr:ndr@localhost:5432/ndr?sslmode=disable"
	}
	return url
}

func migrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/repository/postgres -> repo root
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	return filepath.Join(root, "migrations")
}

func runGoose(t *testing.T, databaseURL, command string) {
	t.Helper()
	cmd := exec.Command("goose", "-dir", migrationsDir(t), "postgres", databaseURL, command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("goose %s failed: %v\n%s", command, err, out)
	}
	t.Logf("goose %s:\n%s", command, out)
}

func TestMigrationsAndRepositories(t *testing.T) {
	if _, err := exec.LookPath("goose"); err != nil {
		t.Skip("goose CLI not installed")
	}

	ctx := context.Background()
	dbURL := testDatabaseURL(t)

	pool, err := postgres.Connect(ctx, dbURL)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer pool.Close()

	// Apply migrations to the running empty/dev database. Do not drop the Docker volume.
	runGoose(t, dbURL, "up")
	runGoose(t, dbURL, "status")

	store := postgres.NewStore(pool)

	now := time.Now().UTC().Truncate(time.Millisecond)
	batchID := uuid.New()
	flowID := uuid.New()
	srcMAC := "00:1A:2B:3C:4D:5E"
	dstMAC := "AA:BB:CC:DD:EE:FF"
	srcIP := netip.MustParseAddr("192.168.1.50")
	dstIP := netip.MustParseAddr("10.0.0.5")

	srcNodeID := domain.MakeNodeID(&srcMAC, srcIP)
	dstNodeID := domain.MakeNodeID(&dstMAC, dstIP)

	err = store.WithinTx(ctx, func(tx pgx.Tx) error {
		if err := store.InsertFlows(ctx, tx, []domain.Flow{{
			ID:           flowID,
			BatchID:      batchID,
			SensorID:     "core_switch_mirror",
			ObservedAt:   now,
			SrcIP:        srcIP,
			SrcMAC:       &srcMAC,
			DstIP:        dstIP,
			DstMAC:       &dstMAC,
			SrcPort:      54321,
			DstPort:      443,
			Protocol:     "TCP",
			DurationMs:   1500,
			TotalPackets: 45,
			TotalBytes:   35000,
			TCPFlags:     domain.TCPFlags{SYN: 1, ACK: 40, RST: 0},
		}}); err != nil {
			return err
		}
		if err := store.UpsertNode(ctx, tx, domain.Node{
			ID: srcNodeID, MACAddress: &srcMAC, IPAddress: srcIP,
			FirstSeen: now, LastSeen: now,
		}); err != nil {
			return err
		}
		if err := store.UpsertNode(ctx, tx, domain.Node{
			ID: dstNodeID, MACAddress: &dstMAC, IPAddress: dstIP,
			FirstSeen: now, LastSeen: now,
		}); err != nil {
			return err
		}
		return store.UpsertEdge(ctx, tx, domain.Edge{
			ID: uuid.New(), SourceNodeID: srcNodeID, TargetNodeID: dstNodeID,
			Protocol: "TCP", TotalBytes: 35000, TotalPackets: 45, LastSeen: now,
		})
	})
	if err != nil {
		t.Fatalf("transaction failed: %v", err)
	}

	gotFlow, err := store.GetFlowByID(ctx, flowID)
	if err != nil {
		t.Fatalf("GetFlowByID: %v", err)
	}
	if gotFlow.TotalBytes != 35000 || gotFlow.Protocol != "TCP" {
		t.Fatalf("unexpected flow: %+v", gotFlow)
	}

	nodes, err := store.ListNodes(ctx)
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) < 2 {
		t.Fatalf("expected >=2 nodes, got %d", len(nodes))
	}

	edges, err := store.ListEdges(ctx)
	if err != nil {
		t.Fatalf("ListEdges: %v", err)
	}
	if len(edges) < 1 {
		t.Fatalf("expected >=1 edge")
	}

	// Second upsert accumulates counters.
	err = store.WithinTx(ctx, func(tx pgx.Tx) error {
		return store.UpsertEdge(ctx, tx, domain.Edge{
			ID: uuid.New(), SourceNodeID: srcNodeID, TargetNodeID: dstNodeID,
			Protocol: "TCP", TotalBytes: 1000, TotalPackets: 5, LastSeen: now.Add(time.Second),
		})
	})
	if err != nil {
		t.Fatalf("edge upsert 2: %v", err)
	}
	edges, err = store.ListEdges(ctx)
	if err != nil {
		t.Fatalf("ListEdges 2: %v", err)
	}
	found := false
	for _, e := range edges {
		if e.SourceNodeID == srcNodeID && e.TargetNodeID == dstNodeID && e.Protocol == "TCP" {
			found = true
			if e.TotalBytes < 36000 {
				t.Fatalf("expected accumulated bytes >= 36000, got %d", e.TotalBytes)
			}
		}
	}
	if !found {
		t.Fatal("edge not found after upsert")
	}

	// UpsertNode merges observation windows: older first_seen, newer last_seen.
	t.Run("UpsertNodeSeenTimestamps", func(t *testing.T) {
		// Unique per run so leftover rows from prior integration runs cannot affect LEAST.
		u := uuid.New()
		mac := fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", u[0], u[1], u[2], u[3], u[4], u[5])
		ip := netip.AddrFrom4([4]byte{10, byte(u[6]), byte(u[7]), byte(u[8])})
		nodeID := domain.MakeNodeID(&mac, ip)
		mid := now.Add(time.Hour)
		early := now.Add(-2 * time.Hour)
		late := now.Add(3 * time.Hour)

		err := store.WithinTx(ctx, func(tx pgx.Tx) error {
			return store.UpsertNode(ctx, tx, domain.Node{
				ID: nodeID, MACAddress: &mac, IPAddress: ip,
				FirstSeen: mid, LastSeen: mid,
			})
		})
		if err != nil {
			t.Fatalf("initial upsert: %v", err)
		}

		err = store.WithinTx(ctx, func(tx pgx.Tx) error {
			return store.UpsertNode(ctx, tx, domain.Node{
				ID: nodeID, MACAddress: &mac, IPAddress: ip,
				FirstSeen: early, LastSeen: early,
			})
		})
		if err != nil {
			t.Fatalf("older observation upsert: %v", err)
		}

		err = store.WithinTx(ctx, func(tx pgx.Tx) error {
			return store.UpsertNode(ctx, tx, domain.Node{
				ID: nodeID, MACAddress: &mac, IPAddress: ip,
				FirstSeen: late, LastSeen: late,
			})
		})
		if err != nil {
			t.Fatalf("newer observation upsert: %v", err)
		}

		nodes, err := store.ListNodes(ctx)
		if err != nil {
			t.Fatalf("ListNodes: %v", err)
		}
		var got *domain.Node
		for i := range nodes {
			if nodes[i].ID == nodeID {
				got = &nodes[i]
				break
			}
		}
		if got == nil {
			t.Fatalf("node %s not found", nodeID)
		}
		if !got.FirstSeen.Equal(early) {
			t.Fatalf("first_seen=%v, want %v (LEAST)", got.FirstSeen.UTC(), early.UTC())
		}
		if !got.LastSeen.Equal(late) {
			t.Fatalf("last_seen=%v, want %v (GREATEST)", got.LastSeen.UTC(), late.UTC())
		}
	})

	incID := uuid.New()
	fid := flowID
	err = store.InsertIncident(ctx, nil, domain.Incident{
		ID:                incID,
		FlowID:            &fid,
		SrcIP:             srcIP,
		SrcMAC:            &srcMAC,
		DstIP:             dstIP,
		DstMAC:            &dstMAC,
		AttackClass:       domain.AttackPortScan,
		Severity:          domain.SeverityMedium,
		Status:            domain.StatusOpen,
		MLConfidence:      0.72,
		AgentVerdict:      "test verdict",
		RecommendedAction: "Проверьте источник после подтверждения оператором",
		ContextSummary:    json.RawMessage(`{"test":true}`),
	})
	if err != nil {
		t.Fatalf("InsertIncident: %v", err)
	}
	gotInc, err := store.GetIncidentByID(ctx, incID)
	if err != nil {
		t.Fatalf("GetIncidentByID: %v", err)
	}
	if gotInc.AttackClass != domain.AttackPortScan {
		t.Fatalf("unexpected incident: %+v", gotInc)
	}

	schedID := uuid.New()
	src := srcIP
	err = store.InsertWhitelistSchedule(ctx, domain.WhitelistSchedule{
		ID:        schedID,
		Name:      "nightly-backup",
		SrcIP:     &src,
		StartTime: time.Date(1970, 1, 1, 1, 0, 0, 0, time.UTC),
		EndTime:   time.Date(1970, 1, 1, 3, 0, 0, 0, time.UTC),
		Enabled:   true,
	})
	if err != nil {
		t.Fatalf("InsertWhitelistSchedule: %v", err)
	}
	schedules, err := store.ListEnabledWhitelistSchedules(ctx)
	if err != nil {
		t.Fatalf("ListEnabledWhitelistSchedules: %v", err)
	}
	if len(schedules) < 1 {
		t.Fatal("expected enabled schedule")
	}

	// Re-run up should be a no-op (safe to rerun).
	runGoose(t, dbURL, "up")
}
