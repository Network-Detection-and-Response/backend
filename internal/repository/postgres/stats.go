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

// TCPFlagTotals is the sum of TCP flag counters over the overview window.
type TCPFlagTotals struct {
	SYN int64
	ACK int64
	RST int64
}

// SensorActivity is derived from stored network_flows (batch timestamps), not a dedicated heartbeat.
type SensorActivity struct {
	SensorID    string
	LastBatchAt time.Time
	FlowsLast5m int64
	Activity    string // active | idle | stale — never "online"
}

// OverviewStats is the dashboard overview aggregate.
type OverviewStats struct {
	FlowsTotal          int64
	BytesTotal          int64
	PacketsTotal        int64
	IncidentsTotal      int64
	IncidentsBySeverity map[string]int64
	Protocols           []ProtocolStat
	TCPFlags            TCPFlagTotals
	Sensors             []SensorActivity
}

// MinuteBucket is one UTC minute aggregate for timeseries stats.
type MinuteBucket struct {
	Minute  time.Time
	Flows   int64
	Packets int64
	Bytes   int64
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
		Sensors:   []SensorActivity{},
	}

	err := s.pool.QueryRow(ctx, `
SELECT COUNT(*), COALESCE(SUM(total_bytes), 0), COALESCE(SUM(total_packets), 0),
       COALESCE(SUM(tcp_syn), 0), COALESCE(SUM(tcp_ack), 0), COALESCE(SUM(tcp_rst), 0)
FROM network_flows
WHERE observed_at >= $1`, since).Scan(
		&out.FlowsTotal, &out.BytesTotal, &out.PacketsTotal,
		&out.TCPFlags.SYN, &out.TCPFlags.ACK, &out.TCPFlags.RST,
	)
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
	if err := prows.Err(); err != nil {
		return OverviewStats{}, err
	}

	sensors, err := s.loadSensorActivity(ctx, time.Now().UTC())
	if err != nil {
		return OverviewStats{}, err
	}
	out.Sensors = sensors
	return out, nil
}

// loadSensorActivity derives sensor liveness from network_flows.observed_at (batch timestamp).
// Lookback is 24h so the query can use network_flows_observed_at_idx.
func (s *Store) loadSensorActivity(ctx context.Context, now time.Time) ([]SensorActivity, error) {
	now = now.UTC()
	since5m := now.Add(-5 * time.Minute)
	since24h := now.Add(-24 * time.Hour)

	rows, err := s.pool.Query(ctx, `
SELECT sensor_id,
       MAX(observed_at) AS last_batch_at,
       COUNT(*) FILTER (WHERE observed_at >= $1) AS flows_last_5m
FROM network_flows
WHERE observed_at >= $2
GROUP BY sensor_id
ORDER BY last_batch_at DESC, sensor_id ASC`, since5m, since24h)
	if err != nil {
		return nil, fmt.Errorf("sensor activity: %w", err)
	}
	defer rows.Close()

	out := make([]SensorActivity, 0)
	for rows.Next() {
		var sa SensorActivity
		if err := rows.Scan(&sa.SensorID, &sa.LastBatchAt, &sa.FlowsLast5m); err != nil {
			return nil, err
		}
		sa.LastBatchAt = sa.LastBatchAt.UTC()
		sa.Activity = ClassifySensorActivity(now, sa.LastBatchAt)
		out = append(out, sa)
	}
	return out, rows.Err()
}

// ClassifySensorActivity documents the activity rule used in API responses.
//   - active: last batch within 2 minutes
//   - idle:   last batch within 15 minutes
//   - stale:  older than 15 minutes
//
// Never returns "online" — batch timestamps are not a dedicated heartbeat.
func ClassifySensorActivity(now, lastBatchAt time.Time) string {
	age := now.UTC().Sub(lastBatchAt.UTC())
	switch {
	case age <= 2*time.Minute:
		return "active"
	case age <= 15*time.Minute:
		return "idle"
	default:
		return "stale"
	}
}

// LoadMinuteBuckets returns sparse UTC minute aggregates in [since, until).
// Callers fill empty minutes. Uses epoch flooring so buckets are timezone-stable.
func (s *Store) LoadMinuteBuckets(ctx context.Context, since, until time.Time) ([]MinuteBucket, error) {
	since = since.UTC()
	until = until.UTC()
	rows, err := s.pool.Query(ctx, `
SELECT to_timestamp(floor(extract(epoch FROM observed_at) / 60) * 60) AS minute,
       COUNT(*)::bigint,
       COALESCE(SUM(total_packets), 0)::bigint,
       COALESCE(SUM(total_bytes), 0)::bigint
FROM network_flows
WHERE observed_at >= $1 AND observed_at < $2
GROUP BY 1
ORDER BY 1 ASC`, since, until)
	if err != nil {
		return nil, fmt.Errorf("minute buckets: %w", err)
	}
	defer rows.Close()

	out := make([]MinuteBucket, 0)
	for rows.Next() {
		var b MinuteBucket
		if err := rows.Scan(&b.Minute, &b.Flows, &b.Packets, &b.Bytes); err != nil {
			return nil, err
		}
		b.Minute = b.Minute.UTC()
		out = append(out, b)
	}
	return out, rows.Err()
}
