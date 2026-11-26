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

// Store loads overview and timeseries aggregates.
type Store interface {
	LoadOverviewStats(ctx context.Context, since time.Time) (postgres.OverviewStats, error)
	LoadMinuteBuckets(ctx context.Context, since, until time.Time) ([]postgres.MinuteBucket, error)
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
	TCPFlags            TCPFlagsItem
	Sensors             []SensorItem
}

type ProtocolItem struct {
	Protocol string `json:"protocol"`
	Flows    int64  `json:"flows"`
	Bytes    int64  `json:"bytes"`
	Packets  int64  `json:"packets"`
}

// TCPFlagsItem mirrors SUM(tcp_syn/ack/rst) for the overview window.
type TCPFlagsItem struct {
	SYN int64 `json:"syn"`
	ACK int64 `json:"ack"`
	RST int64 `json:"rst"`
}

// SensorItem is derived sensor activity (not a push heartbeat).
type SensorItem struct {
	SensorID    string `json:"sensor_id"`
	LastBatchAt string `json:"last_batch_at"`
	FlowsLast5m int64  `json:"flows_last_5m"`
	Activity    string `json:"activity"`
}

// Timeseries is the API model for GET /stats/timeseries.
type Timeseries struct {
	Period   string
	Bucket   string
	Timezone string
	From     time.Time
	To       time.Time
	Points   []TimeseriesPoint
}

type TimeseriesPoint struct {
	T       string `json:"t"`
	Flows   int64  `json:"flows"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
}

// Service builds overview statistics for a requested period.
type Service struct {
	store Store
	now   func() time.Time
}

func NewService(store Store) *Service {
	return &Service{store: store, now: time.Now}
}

// NewServiceWithClock is used by tests to inject a fixed clock.
func NewServiceWithClock(store Store, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, now: now}
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
	sensors := make([]SensorItem, 0, len(raw.Sensors))
	for _, sa := range raw.Sensors {
		sensors = append(sensors, SensorItem{
			SensorID:    sa.SensorID,
			LastBatchAt: sa.LastBatchAt.UTC().Format(time.RFC3339),
			FlowsLast5m: sa.FlowsLast5m,
			Activity:    sa.Activity,
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
		TCPFlags: TCPFlagsItem{
			SYN: raw.TCPFlags.SYN,
			ACK: raw.TCPFlags.ACK,
			RST: raw.TCPFlags.RST,
		},
		Sensors: sensors,
	}, nil
}

// TimeseriesLastHour returns 60 UTC minute buckets for the last hour (inclusive of current minute).
// Minutes without flows are present with zero counters — values are never invented beyond gap-fill zeros.
func (s *Service) TimeseriesLastHour(ctx context.Context) (Timeseries, error) {
	now := s.now().UTC()
	untilExclusive := now.Truncate(time.Minute).Add(time.Minute)
	first := untilExclusive.Add(-60 * time.Minute) // 60 minutes: [first, untilExclusive)

	raw, err := s.store.LoadMinuteBuckets(ctx, first, untilExclusive)
	if err != nil {
		return Timeseries{}, err
	}
	byMinute := make(map[int64]postgres.MinuteBucket, len(raw))
	for _, b := range raw {
		byMinute[b.Minute.UTC().Unix()] = b
	}

	points := make([]TimeseriesPoint, 0, 60)
	for i := 0; i < 60; i++ {
		m := first.Add(time.Duration(i) * time.Minute)
		b := byMinute[m.Unix()]
		points = append(points, TimeseriesPoint{
			T:       m.Format(time.RFC3339),
			Flows:   b.Flows,
			Packets: b.Packets,
			Bytes:   b.Bytes,
		})
	}

	last := first.Add(59 * time.Minute)
	return Timeseries{
		Period:   "1h",
		Bucket:   "1m",
		Timezone: "UTC",
		From:     first,
		To:       last, // inclusive start of the last 1-minute bucket
		Points:   points,
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
