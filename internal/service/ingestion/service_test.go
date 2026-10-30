package ingestion

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type mockStore struct {
	failInsert bool
	flows      []domain.Flow
	nodes      []domain.Node
	edges      []domain.Edge
}

func (m *mockStore) WithinTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return fn(nil)
}

func (m *mockStore) InsertFlows(ctx context.Context, tx pgx.Tx, flows []domain.Flow) error {
	if m.failInsert {
		return errors.New("insert failed")
	}
	m.flows = append(m.flows, flows...)
	return nil
}

func (m *mockStore) UpsertNode(ctx context.Context, tx pgx.Tx, node domain.Node) error {
	m.nodes = append(m.nodes, node)
	return nil
}

func (m *mockStore) UpsertEdge(ctx context.Context, tx pgx.Tx, edge domain.Edge) error {
	m.edges = append(m.edges, edge)
	return nil
}

func TestServiceProcessBatchPersistsTopology(t *testing.T) {
	store := &mockStore{}
	svc := NewService(store)
	now := time.Date(2026, 10, 9, 14, 30, 0, 0, time.UTC)
	srcMAC := "00:1A:2B:3C:4D:5E"
	job := BatchJob{
		BatchID:    uuid.New(),
		SensorID:   "s1",
		ObservedAt: now,
		Flows: []domain.Flow{{
			ID: uuid.New(), BatchID: uuid.New(), SensorID: "s1", ObservedAt: now,
			SrcIP: netip.MustParseAddr("192.168.1.50"), SrcMAC: &srcMAC,
			DstIP: netip.MustParseAddr("10.0.0.5"), DstMAC: nil,
			SrcPort: 1, DstPort: 80, Protocol: "TCP",
			TotalPackets: 2, TotalBytes: 100,
		}},
	}
	if err := svc.ProcessBatch(context.Background(), job); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if len(store.flows) != 1 {
		t.Fatalf("flows=%d", len(store.flows))
	}
	if len(store.nodes) != 2 {
		t.Fatalf("nodes=%d want 2 (mac + ip-only)", len(store.nodes))
	}
	if len(store.edges) != 1 {
		t.Fatalf("edges=%d", len(store.edges))
	}
	foundIPOnly := false
	for _, n := range store.nodes {
		if n.ID == "ip:10.0.0.5" {
			foundIPOnly = true
		}
	}
	if !foundIPOnly {
		t.Fatal("expected IP-based node id for null dst MAC")
	}
}

func TestServiceProcessBatchPropagatesDBError(t *testing.T) {
	store := &mockStore{failInsert: true}
	svc := NewService(store)
	err := svc.ProcessBatch(context.Background(), BatchJob{
		Flows: []domain.Flow{{
			ID: uuid.New(), SrcIP: netip.MustParseAddr("1.1.1.1"), DstIP: netip.MustParseAddr("2.2.2.2"),
			Protocol: "UDP", ObservedAt: time.Now().UTC(),
		}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}
