package stats

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
)

var (
	ErrValidation = fmt.Errorf("validation error")
)

// Store loads overview aggregates.
type Store interface {
	LoadOverviewStats(ctx context.Context, since time.Time) (postgres.OverviewStats, error)
}

// Overview is the API response model for /stats/overview.
type Overview struct {
	Period              string
	FlowsTotal          int64
	BytesTotal          int64
	PacketsTotal        int64
	IncidentsTotal      int64
	IncidentsBySeverity map[string]int64
	Protocols           []ProtocolItem
}

type ProtocolItem struct {
	Protocol string `json:"protocol"`
	Flows    int64  `json:"flows"`
	Bytes    int64  `json:"bytes"`
	Packets  int64  `json:"packets"`
}

// Service builds overview statistics for a requested period.
type Service struct {
	store Store
	now   func() time.Time
}

func NewService(store Store) *Service {
	return &Service{store: store, now: time.Now}
}

// Overview returns aggregates for period (default 24h). Supported: 1h, 24h, 7d, or Go duration.
func (s *Service) Overview(ctx context.Context, period string) (Overview, error) {
	period = strings.TrimSpace(period)
	if period == "" {
		period = "24h"
	}
	dur, err := parsePeriod(period)
	if err != nil {
		return Overview{}, fmt.Errorf("%w: %s", ErrValidation, err.Error())
	}
	since := s.now().UTC().Add(-dur)
	raw, err := s.store.LoadOverviewStats(ctx, since)
	if err != nil {
		return Overview{}, err
	}
	protocols := make([]ProtocolItem, 0, len(raw.Protocols))
	for _, p := range raw.Protocols {
		protocols = append(protocols, ProtocolItem{
			Protocol: p.Protocol,
			Flows:    p.Flows,
			Bytes:    p.Bytes,
			Packets:  p.Packets,
		})
	}
	return Overview{
		Period:              period,
		FlowsTotal:          raw.FlowsTotal,
		BytesTotal:          raw.BytesTotal,
		PacketsTotal:        raw.PacketsTotal,
		IncidentsTotal:      raw.IncidentsTotal,
		IncidentsBySeverity: raw.IncidentsBySeverity,
		Protocols:           protocols,
	}, nil
}

func parsePeriod(period string) (time.Duration, error) {
	switch strings.ToLower(period) {
	case "1h":
		return time.Hour, nil
	case "24h":
		return 24 * time.Hour, nil
	case "7d":
		return 7 * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(period)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("period must be 1h, 24h, 7d, or a positive Go duration")
	}
	// Cap absurd windows for the course project.
	if d > 30*24*time.Hour {
		return 0, fmt.Errorf("period must not exceed 30d")
	}
	return d, nil
}
