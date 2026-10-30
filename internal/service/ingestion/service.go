package ingestion

import (
	"context"
	"fmt"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// BatchStore is the persistence surface used by the ingestion processor.
type BatchStore interface {
	WithinTx(ctx context.Context, fn func(tx pgx.Tx) error) error
	InsertFlows(ctx context.Context, tx pgx.Tx, flows []domain.Flow) error
	UpsertNode(ctx context.Context, tx pgx.Tx, node domain.Node) error
	UpsertEdge(ctx context.Context, tx pgx.Tx, edge domain.Edge) error
}

// Service persists accepted batches (flows + node/edge aggregates) transactionally.
// ML / decision agent are intentionally not invoked in this phase.
type Service struct {
	store BatchStore
}

// NewService constructs an ingestion processor.
func NewService(store BatchStore) *Service {
	return &Service{store: store}
}

// ProcessBatch inserts all flows and upserts observed nodes/edges in one transaction.
func (s *Service) ProcessBatch(ctx context.Context, job BatchJob) error {
	if len(job.Flows) == 0 {
		return nil
	}

	nodes, edges := aggregateTopology(job)

	return s.store.WithinTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.InsertFlows(ctx, tx, job.Flows); err != nil {
			return fmt.Errorf("insert flows: %w", err)
		}
		for _, n := range nodes {
			if err := s.store.UpsertNode(ctx, tx, n); err != nil {
				return err
			}
		}
		for _, e := range edges {
			if err := s.store.UpsertEdge(ctx, tx, e); err != nil {
				return err
			}
		}
		return nil
	})
}

func aggregateTopology(job BatchJob) ([]domain.Node, []domain.Edge) {
	nodeMap := make(map[string]domain.Node)
	type edgeKey struct {
		src, dst, proto string
	}
	edgeMap := make(map[edgeKey]domain.Edge)

	for _, f := range job.Flows {
		srcID := domain.MakeNodeID(f.SrcMAC, f.SrcIP)
		dstID := domain.MakeNodeID(f.DstMAC, f.DstIP)

		upsertNodeLocal(nodeMap, domain.Node{
			ID:         srcID,
			MACAddress: f.SrcMAC,
			IPAddress:  f.SrcIP,
			DeviceType: "unknown",
			FirstSeen:  f.ObservedAt,
			LastSeen:   f.ObservedAt,
		})
		upsertNodeLocal(nodeMap, domain.Node{
			ID:         dstID,
			MACAddress: f.DstMAC,
			IPAddress:  f.DstIP,
			DeviceType: "unknown",
			FirstSeen:  f.ObservedAt,
			LastSeen:   f.ObservedAt,
		})

		k := edgeKey{src: srcID, dst: dstID, proto: f.Protocol}
		if existing, ok := edgeMap[k]; ok {
			existing.TotalBytes += f.TotalBytes
			existing.TotalPackets += f.TotalPackets
			if f.ObservedAt.After(existing.LastSeen) {
				existing.LastSeen = f.ObservedAt
			}
			edgeMap[k] = existing
		} else {
			edgeMap[k] = domain.Edge{
				ID:           uuid.New(),
				SourceNodeID: srcID,
				TargetNodeID: dstID,
				Protocol:     f.Protocol,
				TotalBytes:   f.TotalBytes,
				TotalPackets: f.TotalPackets,
				LastSeen:     f.ObservedAt,
			}
		}
	}

	nodes := make([]domain.Node, 0, len(nodeMap))
	for _, n := range nodeMap {
		nodes = append(nodes, n)
	}
	edges := make([]domain.Edge, 0, len(edgeMap))
	for _, e := range edgeMap {
		edges = append(edges, e)
	}
	return nodes, edges
}

func upsertNodeLocal(m map[string]domain.Node, n domain.Node) {
	if prev, ok := m[n.ID]; ok {
		if n.LastSeen.After(prev.LastSeen) {
			prev.LastSeen = n.LastSeen
			prev.IPAddress = n.IPAddress
			if n.MACAddress != nil {
				prev.MACAddress = n.MACAddress
			}
		}
		if n.FirstSeen.Before(prev.FirstSeen) {
			prev.FirstSeen = n.FirstSeen
		}
		m[n.ID] = prev
		return
	}
	m[n.ID] = n
}
