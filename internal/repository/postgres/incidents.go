package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// IncidentListFilter holds validated list query parameters.
type IncidentListFilter struct {
	Page     int
	PageSize int
	Severity *string
	Status   *string
	Since    *time.Time
	Until    *time.Time
}

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

// HasIncidentForFlowID reports whether an incident already exists for the flow.
// Used to avoid duplicate incidents if scoring is re-entered for the same flow.
func (s *Store) HasIncidentForFlowID(ctx context.Context, flowID uuid.UUID) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM incidents WHERE flow_id = $1)`,
		flowID,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("has incident for flow: %w", err)
	}
	return exists, nil
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

// ListIncidents returns a page of incidents and the total matching count.
func (s *Store) ListIncidents(ctx context.Context, f IncidentListFilter) ([]domain.Incident, int64, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.PageSize < 1 {
		f.PageSize = 20
	}
	if f.PageSize > 100 {
		f.PageSize = 100
	}

	where, args := buildIncidentWhere(f)
	countQ := `SELECT COUNT(*) FROM incidents` + where
	var total int64
	if err := s.pool.QueryRow(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count incidents: %w", err)
	}

	offset := (f.Page - 1) * f.PageSize
	args = append(args, f.PageSize, offset)
	listQ := `
SELECT id, flow_id, created_at, src_ip, src_mac::text, dst_ip, dst_mac::text,
       attack_class, severity, status, ml_confidence,
       agent_verdict, recommended_action, context_summary
FROM incidents` + where + `
ORDER BY created_at DESC
LIMIT $` + itoa(len(args)-1) + ` OFFSET $` + itoa(len(args))

	rows, err := s.pool.Query(ctx, listQ, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()

	var out []domain.Incident
	for rows.Next() {
		var inc domain.Incident
		var srcMAC, dstMAC *string
		if err := rows.Scan(
			&inc.ID, &inc.FlowID, &inc.CreatedAt, &inc.SrcIP, &srcMAC, &inc.DstIP, &dstMAC,
			&inc.AttackClass, &inc.Severity, &inc.Status, &inc.MLConfidence,
			&inc.AgentVerdict, &inc.RecommendedAction, &inc.ContextSummary,
		); err != nil {
			return nil, 0, err
		}
		inc.SrcMAC = srcMAC
		inc.DstMAC = dstMAC
		out = append(out, inc)
	}
	if out == nil {
		out = []domain.Incident{}
	}
	return out, total, rows.Err()
}

// UpdateIncidentStatus sets a new status after transition validation by the caller.
func (s *Store) UpdateIncidentStatus(ctx context.Context, id uuid.UUID, status string) (domain.Incident, error) {
	const q = `
UPDATE incidents SET status = $2
WHERE id = $1
RETURNING id, flow_id, created_at, src_ip, src_mac::text, dst_ip, dst_mac::text,
          attack_class, severity, status, ml_confidence,
          agent_verdict, recommended_action, context_summary`
	var inc domain.Incident
	var srcMAC, dstMAC *string
	err := s.pool.QueryRow(ctx, q, id, status).Scan(
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

func buildIncidentWhere(f IncidentListFilter) (string, []any) {
	var parts []string
	var args []any
	add := func(expr string, v any) {
		args = append(args, v)
		parts = append(parts, fmt.Sprintf(expr, len(args)))
	}
	if f.Severity != nil {
		add("severity = $%d", *f.Severity)
	}
	if f.Status != nil {
		add("status = $%d", *f.Status)
	}
	if f.Since != nil {
		add("created_at >= $%d", f.Since.UTC())
	}
	if f.Until != nil {
		add("created_at <= $%d", f.Until.UTC())
	}
	if len(parts) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(parts, " AND "), args
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
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
