package postgres

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// InsertFlows inserts flow rows. Caller should run this inside WithinTx when
// combined with node/edge upserts for the same batch.
func (s *Store) InsertFlows(ctx context.Context, tx pgx.Tx, flows []domain.Flow) error {
	if len(flows) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	const q = `
INSERT INTO network_flows (
    id, batch_id, sensor_id, observed_at,
    src_ip, src_mac, dst_ip, dst_mac,
    src_port, dst_port, protocol,
    duration_ms, total_packets, total_bytes,
    tcp_syn, tcp_ack, tcp_rst
) VALUES (
    $1,$2,$3,$4,
    $5,$6,$7,$8,
    $9,$10,$11,
    $12,$13,$14,
    $15,$16,$17
)`
	for _, f := range flows {
		batch.Queue(q,
			f.ID, f.BatchID, f.SensorID, f.ObservedAt,
			f.SrcIP, f.SrcMAC, f.DstIP, f.DstMAC,
			f.SrcPort, f.DstPort, f.Protocol,
			f.DurationMs, f.TotalPackets, f.TotalBytes,
			f.TCPFlags.SYN, f.TCPFlags.ACK, f.TCPFlags.RST,
		)
	}

	br := tx.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < len(flows); i++ {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("insert flow[%d]: %w", i, err)
		}
	}
	return nil
}

// GetFlowByID returns a flow or pgx.ErrNoRows.
func (s *Store) GetFlowByID(ctx context.Context, id uuid.UUID) (domain.Flow, error) {
	const q = `
SELECT id, batch_id, sensor_id, observed_at,
       src_ip, src_mac::text, dst_ip, dst_mac::text,
       src_port, dst_port, protocol,
       duration_ms, total_packets, total_bytes,
       tcp_syn, tcp_ack, tcp_rst, created_at
FROM network_flows
WHERE id = $1`

	var f domain.Flow
	var srcMAC, dstMAC *string
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&f.ID, &f.BatchID, &f.SensorID, &f.ObservedAt,
		&f.SrcIP, &srcMAC, &f.DstIP, &dstMAC,
		&f.SrcPort, &f.DstPort, &f.Protocol,
		&f.DurationMs, &f.TotalPackets, &f.TotalBytes,
		&f.TCPFlags.SYN, &f.TCPFlags.ACK, &f.TCPFlags.RST, &f.CreatedAt,
	)
	if err != nil {
		return domain.Flow{}, err
	}
	f.SrcMAC = srcMAC
	f.DstMAC = dstMAC
	return f, nil
}

// CountFlows returns the number of stored flows (diagnostics / tests).
func (s *Store) CountFlows(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM network_flows`).Scan(&n)
	return n, err
}

// CountFlowsByBatchID returns how many flows were stored for a batch.
func (s *Store) CountFlowsByBatchID(ctx context.Context, batchID uuid.UUID) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM network_flows WHERE batch_id = $1`, batchID).Scan(&n)
	return n, err
}

// CountRecentFlowsBySrcIP counts flows from srcIP with observed_at >= since (UTC).
// Used as a simple historical aggregate for the decision agent context.
func (s *Store) CountRecentFlowsBySrcIP(ctx context.Context, srcIP netip.Addr, since time.Time) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM network_flows WHERE src_ip = $1 AND observed_at >= $2`,
		srcIP, since.UTC(),
	).Scan(&n)
	return n, err
}

// FlowListItem is a compact projection for GET /api/v1/flows (dashboard Recent flows).
type FlowListItem struct {
	ID           uuid.UUID
	SensorID     string
	ObservedAt   time.Time
	SrcIP        netip.Addr
	DstIP        netip.Addr
	SrcPort      int
	DstPort      int
	Protocol     string
	TotalPackets int64
	TotalBytes   int64
}

// ListRecentFlows returns flows ordered by observed_at DESC, then id DESC for stable paging.
func (s *Store) ListRecentFlows(ctx context.Context, limit, offset int) ([]FlowListItem, int64, error) {
	if limit < 1 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var total int64
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM network_flows`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count flows: %w", err)
	}

	const q = `
SELECT id, sensor_id, observed_at,
       src_ip, dst_ip, src_port, dst_port, protocol,
       total_packets, total_bytes
FROM network_flows
ORDER BY observed_at DESC, id DESC
LIMIT $1 OFFSET $2`

	rows, err := s.pool.Query(ctx, q, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list flows: %w", err)
	}
	defer rows.Close()

	items := make([]FlowListItem, 0, limit)
	for rows.Next() {
		var item FlowListItem
		if err := rows.Scan(
			&item.ID, &item.SensorID, &item.ObservedAt,
			&item.SrcIP, &item.DstIP, &item.SrcPort, &item.DstPort, &item.Protocol,
			&item.TotalPackets, &item.TotalBytes,
		); err != nil {
			return nil, 0, fmt.Errorf("scan flow: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate flows: %w", err)
	}
	return items, total, nil
}
