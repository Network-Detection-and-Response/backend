package stats_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	"github.com/Network-Detection-and-Response/backend/internal/service/stats"
)

type memStats struct {
	out postgres.OverviewStats
	err error
}

func (m *memStats) LoadOverviewStats(ctx context.Context, since time.Time) (postgres.OverviewStats, error) {
	if m.err != nil {
		return postgres.OverviewStats{}, m.err
	}
	return m.out, nil
}

func TestOverviewDefaultPeriod(t *testing.T) {
	svc := stats.NewService(&memStats{out: postgres.OverviewStats{
		FlowsTotal: 3, BytesTotal: 300, PacketsTotal: 30, IncidentsTotal: 1,
		IncidentsBySeverity: map[string]int64{
			domain.SeverityLow: 0, domain.SeverityMedium: 0,
			domain.SeverityHigh: 1, domain.SeverityCritical: 0,
		},
		Protocols: []postgres.ProtocolStat{{Protocol: "TCP", Flows: 3, Bytes: 300, Packets: 30}},
	}})
	ov, err := svc.Overview(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if ov.Period != "24h" || ov.FlowsTotal != 3 || len(ov.Protocols) != 1 {
		t.Fatalf("%+v", ov)
	}
}

func TestOverviewRejectsBadPeriod(t *testing.T) {
	svc := stats.NewService(&memStats{})
	_, err := svc.Overview(context.Background(), "yesterday")
	if !errors.Is(err, stats.ErrValidation) {
		t.Fatalf("err=%v", err)
	}
}

func TestOverviewSupports7d(t *testing.T) {
	svc := stats.NewService(&memStats{out: postgres.OverviewStats{
		IncidentsBySeverity: map[string]int64{
			domain.SeverityLow: 0, domain.SeverityMedium: 0,
			domain.SeverityHigh: 0, domain.SeverityCritical: 0,
		},
		Protocols: []postgres.ProtocolStat{},
	}})
	ov, err := svc.Overview(context.Background(), "7d")
	if err != nil {
		t.Fatal(err)
	}
	if ov.Period != "7d" {
		t.Fatalf("period=%s", ov.Period)
	}
}
