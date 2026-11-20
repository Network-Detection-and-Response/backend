package topology_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	"github.com/Network-Detection-and-Response/backend/internal/service/topology"
	"github.com/google/uuid"
)

type memTopo struct {
	nodes []domain.Node
	edges []domain.Edge
	pairs []postgres.AttackEndpointPair
}

func (m *memTopo) TopologySnapshot(ctx context.Context, attackSince time.Time) ([]domain.Node, []domain.Edge, []postgres.AttackEndpointPair, error) {
	return m.nodes, m.edges, m.pairs, nil
}

func TestTopologyMarksCompromisedAndUnderAttack(t *testing.T) {
	srcMAC := "00:1A:2B:3C:4D:5E"
	srcID := domain.MakeNodeID(&srcMAC, netip.MustParseAddr("192.168.1.50"))
	dstID := domain.MakeNodeID(nil, netip.MustParseAddr("10.0.0.5"))
	edgeID := uuid.New()

	store := &memTopo{
		nodes: []domain.Node{
			{ID: srcID, MACAddress: &srcMAC, IPAddress: netip.MustParseAddr("192.168.1.50"), DeviceType: "unknown", LastSeen: time.Now().UTC()},
			{ID: dstID, IPAddress: netip.MustParseAddr("10.0.0.5"), DeviceType: "unknown", LastSeen: time.Now().UTC()},
		},
		edges: []domain.Edge{
			{ID: edgeID, SourceNodeID: srcID, TargetNodeID: dstID, Protocol: "TCP", TotalBytes: 35000, LastSeen: time.Now().UTC()},
		},
		pairs: []postgres.AttackEndpointPair{{
			SrcIP: netip.MustParseAddr("192.168.1.50"), SrcMAC: &srcMAC,
			DstIP: netip.MustParseAddr("10.0.0.5"),
		}},
	}
	svc := topology.NewService(store, 15*time.Minute)
	g, err := svc.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Nodes) != 2 || len(g.Edges) != 1 {
		t.Fatalf("nodes=%d edges=%d", len(g.Nodes), len(g.Edges))
	}
	compromised := 0
	for _, n := range g.Nodes {
		if n.IsCompromised {
			compromised++
		}
		if n.Label == "" || n.IP == "" {
			t.Fatal("label/ip required")
		}
	}
	if compromised != 2 {
		t.Fatalf("compromised=%d", compromised)
	}
	if !g.Edges[0].IsUnderAttack || g.Edges[0].ID != edgeID.String() {
		t.Fatalf("edge=%+v", g.Edges[0])
	}
}

func TestTopologyEmptyWithoutAttacks(t *testing.T) {
	store := &memTopo{
		nodes: []domain.Node{{ID: "ip:1.1.1.1", IPAddress: netip.MustParseAddr("1.1.1.1"), LastSeen: time.Now().UTC()}},
		edges: []domain.Edge{},
	}
	svc := topology.NewService(store, time.Minute)
	g, err := svc.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if g.Nodes[0].IsCompromised {
		t.Fatal("must not be compromised without active incidents")
	}
	if g.Edges == nil {
		t.Fatal("edges must be empty slice not nil for JSON")
	}
}
