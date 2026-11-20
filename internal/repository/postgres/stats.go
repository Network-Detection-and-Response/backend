package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
)

// ProtocolStat is an aggregate for one protocol in the overview window.
type ProtocolStat struct {
	Protocol string
	Flows    int64
	Bytes    int64
	Packets  int64
}

// OverviewStats is the dashboard overview aggregate.
type OverviewStats struct {
	FlowsTotal          int64
	BytesTotal          int64
	PacketsTotal        int64
	IncidentsTotal      int64
	IncidentsBySeverity map[string]int64
	Protocols           []ProtocolStat
}

// LoadOverviewStats aggregates flows/incidents since the given UTC time.
func (s *Store) LoadOverviewStats(ctx context.Context, since time.Time) (OverviewStats, error) {
	since = since.UTC()
	out := OverviewStats{
		IncidentsBySeverity: map[string]int64{
			domain.SeverityLow:      0,
			domain.SeverityMedium:   0,
			domain.SeverityHigh:     0,
			domain.SeverityCritical: 0,
		},
		Protocols: []ProtocolStat{},
	}

	err := s.pool.QueryRow(ctx, `
SELECT COUNT(*), COALESCE(SUM(total_bytes), 0), COALESCE(SUM(total_packets), 0)
FROM network_flows
WHERE observed_at >= $1`, since).Scan(&out.FlowsTotal, &out.BytesTotal, &out.PacketsTotal)
	if err != nil {
		return OverviewStats{}, fmt.Errorf("overview flow totals: %w", err)
	}

	err = s.pool.QueryRow(ctx, `
SELECT COUNT(*) FROM incidents WHERE created_at >= $1`, since).Scan(&out.IncidentsTotal)
	if err != nil {
		return OverviewStats{}, fmt.Errorf("overview incident total: %w", err)
	}

	rows, err := s.pool.Query(ctx, `
SELECT severity, COUNT(*)
FROM incidents
WHERE created_at >= $1
GROUP BY severity`, since)
	if err != nil {
		return OverviewStats{}, fmt.Errorf("overview incidents by severity: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int64
		if err := rows.Scan(&sev, &n); err != nil {
			return OverviewStats{}, err
		}
		out.IncidentsBySeverity[sev] = n
	}
	if err := rows.Err(); err != nil {
		return OverviewStats{}, err
	}

	prows, err := s.pool.Query(ctx, `
SELECT protocol, COUNT(*), COALESCE(SUM(total_bytes), 0), COALESCE(SUM(total_packets), 0)
FROM network_flows
WHERE observed_at >= $1
GROUP BY protocol
ORDER BY COUNT(*) DESC, protocol ASC`, since)
	if err != nil {
		return OverviewStats{}, fmt.Errorf("overview protocols: %w", err)
	}
	defer prows.Close()
	for prows.Next() {
		var p ProtocolStat
		if err := prows.Scan(&p.Protocol, &p.Flows, &p.Bytes, &p.Packets); err != nil {
			return OverviewStats{}, err
		}
		out.Protocols = append(out.Protocols, p)
	}
	return out, prows.Err()
}
