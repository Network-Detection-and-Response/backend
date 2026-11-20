package postgres

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
)

// AttackEndpointPair is one active incident's observed endpoints (for topology flags).
type AttackEndpointPair struct {
	SrcIP  netip.Addr
	SrcMAC *string
	DstIP  netip.Addr
	DstMAC *string
}

// ListActiveAttackPairs returns endpoints from incidents that are still active
// (OPEN or ACKNOWLEDGED) and created_at >= since (UTC).
// Used to compute is_compromised / is_under_attack at read time.
func (s *Store) ListActiveAttackPairs(ctx context.Context, since time.Time) ([]AttackEndpointPair, error) {
	const q = `
SELECT src_ip, src_mac::text, dst_ip, dst_mac::text
FROM incidents
WHERE created_at >= $1
  AND status IN ('OPEN', 'ACKNOWLEDGED')`

	rows, err := s.pool.Query(ctx, q, since.UTC())
	if err != nil {
		return nil, fmt.Errorf("list active attack pairs: %w", err)
	}
	defer rows.Close()

	var out []AttackEndpointPair
	for rows.Next() {
		var p AttackEndpointPair
		var srcMAC, dstMAC *string
		if err := rows.Scan(&p.SrcIP, &srcMAC, &p.DstIP, &dstMAC); err != nil {
			return nil, err
		}
		p.SrcMAC = srcMAC
		p.DstMAC = dstMAC
		out = append(out, p)
	}
	return out, rows.Err()
}

// TopologySnapshot loads nodes, edges and active attack pairs for the attack window.
func (s *Store) TopologySnapshot(ctx context.Context, attackSince time.Time) ([]domain.Node, []domain.Edge, []AttackEndpointPair, error) {
	nodes, err := s.ListNodes(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	edges, err := s.ListEdges(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	pairs, err := s.ListActiveAttackPairs(ctx, attackSince)
	if err != nil {
		return nil, nil, nil, err
	}
	return nodes, edges, pairs, nil
}
