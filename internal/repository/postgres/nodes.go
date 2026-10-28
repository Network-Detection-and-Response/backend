package postgres

import (
	"context"
	"fmt"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/jackc/pgx/v5"
)

// UpsertNode inserts a node or refreshes last_seen / ip when it already exists.
func (s *Store) UpsertNode(ctx context.Context, tx pgx.Tx, node domain.Node) error {
	const q = `
INSERT INTO network_nodes (
    id, mac_address, ip_address, device_type, first_seen, last_seen, is_compromised, updated_at
) VALUES ($1,$2,$3,COALESCE(NULLIF($4,''),'unknown'),$5,$6,$7,now())
ON CONFLICT (id) DO UPDATE SET
    ip_address = EXCLUDED.ip_address,
    last_seen = GREATEST(network_nodes.last_seen, EXCLUDED.last_seen),
    updated_at = now()
`
	deviceType := node.DeviceType
	if deviceType == "" {
		deviceType = "unknown"
	}
	_, err := tx.Exec(ctx, q,
		node.ID, node.MACAddress, node.IPAddress, deviceType,
		node.FirstSeen, node.LastSeen, node.IsCompromised,
	)
	if err != nil {
		return fmt.Errorf("upsert node %s: %w", node.ID, err)
	}
	return nil
}

// ListNodes returns all nodes ordered by last_seen descending.
func (s *Store) ListNodes(ctx context.Context) ([]domain.Node, error) {
	const q = `
SELECT id, mac_address::text, ip_address, device_type, first_seen, last_seen, is_compromised, updated_at
FROM network_nodes
ORDER BY last_seen DESC`

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Node
	for rows.Next() {
		var n domain.Node
		var mac *string
		if err := rows.Scan(
			&n.ID, &mac, &n.IPAddress, &n.DeviceType,
			&n.FirstSeen, &n.LastSeen, &n.IsCompromised, &n.UpdatedAt,
		); err != nil {
			return nil, err
		}
		n.MACAddress = mac
		out = append(out, n)
	}
	return out, rows.Err()
}

// UpsertEdge accumulates bytes/packets for an observed communication pair.
func (s *Store) UpsertEdge(ctx context.Context, tx pgx.Tx, edge domain.Edge) error {
	const q = `
INSERT INTO network_edges (
    id, source_node_id, target_node_id, protocol, total_bytes, total_packets, last_seen, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,now())
ON CONFLICT (source_node_id, target_node_id, protocol) DO UPDATE SET
    total_bytes = network_edges.total_bytes + EXCLUDED.total_bytes,
    total_packets = network_edges.total_packets + EXCLUDED.total_packets,
    last_seen = GREATEST(network_edges.last_seen, EXCLUDED.last_seen),
    updated_at = now()
`
	_, err := tx.Exec(ctx, q,
		edge.ID, edge.SourceNodeID, edge.TargetNodeID, edge.Protocol,
		edge.TotalBytes, edge.TotalPackets, edge.LastSeen,
	)
	if err != nil {
		return fmt.Errorf("upsert edge %s->%s/%s: %w", edge.SourceNodeID, edge.TargetNodeID, edge.Protocol, err)
	}
	return nil
}

// ListEdges returns all edges ordered by last_seen descending.
func (s *Store) ListEdges(ctx context.Context) ([]domain.Edge, error) {
	const q = `
SELECT id, source_node_id, target_node_id, protocol, total_bytes, total_packets, last_seen, updated_at
FROM network_edges
ORDER BY last_seen DESC`

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Edge
	for rows.Next() {
		var e domain.Edge
		if err := rows.Scan(
			&e.ID, &e.SourceNodeID, &e.TargetNodeID, &e.Protocol,
			&e.TotalBytes, &e.TotalPackets, &e.LastSeen, &e.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
