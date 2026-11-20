package topology

import (
	"context"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
)

// Store loads topology snapshot data.
type Store interface {
	TopologySnapshot(ctx context.Context, attackSince time.Time) ([]domain.Node, []domain.Edge, []postgres.AttackEndpointPair, error)
}

// Graph is the API-facing observed communication map.
type Graph struct {
	Nodes []NodeView
	Edges []EdgeView
}

type NodeView struct {
	ID            string
	Label         string
	IP            string
	MAC           *string
	DeviceType    string
	IsCompromised bool
	LastSeen      time.Time
}

type EdgeView struct {
	ID            string
	Source        string
	Target        string
	Protocol      string
	TotalBytes    int64
	IsUnderAttack bool
	LastSeen      time.Time
}

// Service builds topology views with attack flags computed for AttackWindow.
type Service struct {
	store        Store
	attackWindow time.Duration
	now          func() time.Time
}

func NewService(store Store, attackWindow time.Duration) *Service {
	if attackWindow <= 0 {
		attackWindow = 15 * time.Minute
	}
	return &Service{
		store:        store,
		attackWindow: attackWindow,
		now:          time.Now,
	}
}

// Get returns observed nodes/edges. is_compromised / is_under_attack come from
// OPEN|ACKNOWLEDGED incidents created within AttackWindow (UTC), not from a sticky DB flag.
func (s *Service) Get(ctx context.Context) (Graph, error) {
	since := s.now().UTC().Add(-s.attackWindow)
	nodes, edges, pairs, err := s.store.TopologySnapshot(ctx, since)
	if err != nil {
		return Graph{}, err
	}

	compromised := map[string]struct{}{}
	attackedEdges := map[string]struct{}{}
	for _, p := range pairs {
		srcID := domain.MakeNodeID(p.SrcMAC, p.SrcIP)
		dstID := domain.MakeNodeID(p.DstMAC, p.DstIP)
		compromised[srcID] = struct{}{}
		compromised[dstID] = struct{}{}
		attackedEdges[edgeKey(srcID, dstID)] = struct{}{}
	}

	outNodes := make([]NodeView, 0, len(nodes))
	for _, n := range nodes {
		_, hit := compromised[n.ID]
		outNodes = append(outNodes, NodeView{
			ID:            n.ID,
			Label:         n.IPAddress.String(),
			IP:            n.IPAddress.String(),
			MAC:           n.MACAddress,
			DeviceType:    n.DeviceType,
			IsCompromised: hit,
			LastSeen:      n.LastSeen.UTC(),
		})
	}

	outEdges := make([]EdgeView, 0, len(edges))
	for _, e := range edges {
		_, hit := attackedEdges[edgeKey(e.SourceNodeID, e.TargetNodeID)]
		outEdges = append(outEdges, EdgeView{
			ID:            e.ID.String(),
			Source:        e.SourceNodeID,
			Target:        e.TargetNodeID,
			Protocol:      e.Protocol,
			TotalBytes:    e.TotalBytes,
			IsUnderAttack: hit,
			LastSeen:      e.LastSeen.UTC(),
		})
	}

	if outNodes == nil {
		outNodes = []NodeView{}
	}
	if outEdges == nil {
		outEdges = []EdgeView{}
	}
	return Graph{Nodes: outNodes, Edges: outEdges}, nil
}

func edgeKey(src, dst string) string {
	return src + "->" + dst
}
