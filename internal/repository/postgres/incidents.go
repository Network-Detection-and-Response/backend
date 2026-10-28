package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type execer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// InsertIncident stores a new incident. Pass tx=nil to use the pool directly.
func (s *Store) InsertIncident(ctx context.Context, tx pgx.Tx, inc domain.Incident) error {
	var ex execer = s.pool
	if tx != nil {
		ex = tx
	}
	summary := inc.ContextSummary
	if len(summary) == 0 {
		summary = json.RawMessage(`{}`)
	}
	status := inc.Status
	if status == "" {
		status = domain.StatusOpen
	}

	var createdAt any
	if !inc.CreatedAt.IsZero() {
		createdAt = inc.CreatedAt.UTC()
	}

	const q = `
INSERT INTO incidents (
    id, flow_id, created_at, src_ip, src_mac, dst_ip, dst_mac,
    attack_class, severity, status, ml_confidence,
    agent_verdict, recommended_action, context_summary
) VALUES (
    $1,$2,COALESCE($3::timestamptz, now()),$4,$5,$6,$7,
    $8,$9,$10,$11,
    $12,$13,$14
)`
	_, err := ex.Exec(ctx, q,
		inc.ID, inc.FlowID, createdAt,
		inc.SrcIP, inc.SrcMAC, inc.DstIP, inc.DstMAC,
		inc.AttackClass, inc.Severity, status, inc.MLConfidence,
		inc.AgentVerdict, inc.RecommendedAction, summary,
	)
	if err != nil {
		return fmt.Errorf("insert incident: %w", err)
	}
	return nil
}

// GetIncidentByID returns one incident or pgx.ErrNoRows.
func (s *Store) GetIncidentByID(ctx context.Context, id uuid.UUID) (domain.Incident, error) {
	const q = `
SELECT id, flow_id, created_at, src_ip, src_mac::text, dst_ip, dst_mac::text,
       attack_class, severity, status, ml_confidence,
       agent_verdict, recommended_action, context_summary
FROM incidents
WHERE id = $1`

	var inc domain.Incident
	var srcMAC, dstMAC *string
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&inc.ID, &inc.FlowID, &inc.CreatedAt, &inc.SrcIP, &srcMAC, &inc.DstIP, &dstMAC,
		&inc.AttackClass, &inc.Severity, &inc.Status, &inc.MLConfidence,
		&inc.AgentVerdict, &inc.RecommendedAction, &inc.ContextSummary,
	)
	if err != nil {
		return domain.Incident{}, err
	}
	inc.SrcMAC = srcMAC
	inc.DstMAC = dstMAC
	return inc, nil
}

// ListEnabledWhitelistSchedules returns enabled schedules for the decision agent.
// start_time/end_time and days_of_week are interpreted in UTC by the application.
func (s *Store) ListEnabledWhitelistSchedules(ctx context.Context) ([]domain.WhitelistSchedule, error) {
	const q = `
SELECT id, name, src_ip, src_mac::text, dst_ip, protocol,
       start_time, end_time, days_of_week, enabled, created_at
FROM whitelist_schedules
WHERE enabled = TRUE
ORDER BY created_at`

	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.WhitelistSchedule
	for rows.Next() {
		var w domain.WhitelistSchedule
		var srcMAC, protocol *string
		if err := rows.Scan(
			&w.ID, &w.Name, &w.SrcIP, &srcMAC, &w.DstIP, &protocol,
			&w.StartTime, &w.EndTime, &w.DaysOfWeek, &w.Enabled, &w.CreatedAt,
		); err != nil {
			return nil, err
		}
		w.SrcMAC = srcMAC
		w.Protocol = protocol
		out = append(out, w)
	}
	return out, rows.Err()
}

// InsertWhitelistSchedule stores a schedule rule (tests / admin seed).
func (s *Store) InsertWhitelistSchedule(ctx context.Context, w domain.WhitelistSchedule) error {
	days := w.DaysOfWeek
	if len(days) == 0 {
		days = []int16{0, 1, 2, 3, 4, 5, 6}
	}
	const q = `
INSERT INTO whitelist_schedules (
    id, name, src_ip, src_mac, dst_ip, protocol,
    start_time, end_time, days_of_week, enabled
) VALUES ($1,$2,$3,$4,$5,$6,$7::time,$8::time,$9,$10)`
	_, err := s.pool.Exec(ctx, q,
		w.ID, w.Name, w.SrcIP, w.SrcMAC, w.DstIP, w.Protocol,
		formatClock(w.StartTime), formatClock(w.EndTime), days, w.Enabled,
	)
	return err
}

func formatClock(t time.Time) string {
	if t.IsZero() {
		return "00:00:00"
	}
	return t.UTC().Format("15:04:05")
}
