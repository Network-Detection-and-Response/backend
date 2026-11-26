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
	out       postgres.OverviewStats
	buckets   []postgres.MinuteBucket
	err       error
	bucketErr error
}

func (m *memStats) LoadOverviewStats(ctx context.Context, since time.Time) (postgres.OverviewStats, error) {
	if m.err != nil {
		return postgres.OverviewStats{}, m.err
	}
	return m.out, nil
}

func (m *memStats) LoadMinuteBuckets(ctx context.Context, since, until time.Time) ([]postgres.MinuteBucket, error) {
	if m.bucketErr != nil {
		return nil, m.bucketErr
	}
	return m.buckets, nil
}

func TestOverviewDefaultPeriod(t *testing.T) {
	svc := stats.NewService(&memStats{out: postgres.OverviewStats{
		FlowsTotal: 3, BytesTotal: 300, PacketsTotal: 30, IncidentsTotal: 1,
		IncidentsBySeverity: map[string]int64{
			domain.SeverityLow: 0, domain.SeverityMedium: 0,
			domain.SeverityHigh: 1, domain.SeverityCritical: 0,
		},
		Protocols: []postgres.ProtocolStat{{Protocol: "TCP", Flows: 3, Bytes: 300, Packets: 30}},
		TCPFlags:  postgres.TCPFlagTotals{SYN: 10, ACK: 20, RST: 1},
		Sensors: []postgres.SensorActivity{{
			SensorID: "core_switch_mirror", LastBatchAt: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC),
			FlowsLast5m: 3, Activity: "stale",
		}},
	}})
	ov, err := svc.Overview(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if ov.Period != "24h" || ov.FlowsTotal != 3 || len(ov.Protocols) != 1 {
		t.Fatalf("%+v", ov)
	}
	if ov.TCPFlags.SYN != 10 || ov.TCPFlags.ACK != 20 || ov.TCPFlags.RST != 1 {
		t.Fatalf("tcp_flags=%+v", ov.TCPFlags)
	}
	if len(ov.Sensors) != 1 || ov.Sensors[0].SensorID != "core_switch_mirror" {
		t.Fatalf("sensors=%+v", ov.Sensors)
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
		Sensors:   []postgres.SensorActivity{},
	}})
	ov, err := svc.Overview(context.Background(), "7d")
	if err != nil {
		t.Fatal(err)
	}
	if ov.Period != "7d" {
		t.Fatalf("period=%s", ov.Period)
	}
}

func TestTimeseriesLastHourFillsGaps(t *testing.T) {
	fixed := time.Date(2026, 11, 25, 14, 30, 45, 0, time.UTC)
	first := time.Date(2026, 11, 25, 13, 31, 0, 0, time.UTC)
	hit := time.Date(2026, 11, 25, 14, 0, 0, 0, time.UTC)

	s := stats.NewServiceWithClock(&memStats{
		buckets: []postgres.MinuteBucket{
			{Minute: hit, Flows: 2, Packets: 10, Bytes: 100},
		},
	}, func() time.Time { return fixed })

	ts, err := s.TimeseriesLastHour(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ts.Period != "1h" || ts.Bucket != "1m" || ts.Timezone != "UTC" {
		t.Fatalf("%+v", ts)
	}
	if len(ts.Points) != 60 {
		t.Fatalf("points=%d", len(ts.Points))
	}
	if ts.From != first || ts.Points[0].T != first.Format(time.RFC3339) {
		t.Fatalf("from=%v first_point=%s want %v", ts.From, ts.Points[0].T, first)
	}
	var found bool
	for _, p := range ts.Points {
		if p.T == hit.Format(time.RFC3339) {
			found = true
			if p.Flows != 2 || p.Packets != 10 || p.Bytes != 100 {
				t.Fatalf("hit point=%+v", p)
			}
		}
	}
	if !found {
		t.Fatal("expected populated minute missing")
	}
	zeros := 0
	for _, p := range ts.Points {
		if p.Flows == 0 && p.Packets == 0 && p.Bytes == 0 {
			zeros++
		}
	}
	if zeros != 59 {
		t.Fatalf("zero minutes=%d", zeros)
	}
}

func TestClassifySensorActivity(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		age  time.Duration
		want string
	}{
		{time.Minute, "active"},
		{2 * time.Minute, "active"},
		{3 * time.Minute, "idle"},
		{15 * time.Minute, "idle"},
		{16 * time.Minute, "stale"},
	}
	for _, tc := range cases {
		got := postgres.ClassifySensorActivity(now, now.Add(-tc.age))
		if got != tc.want {
			t.Fatalf("age=%s got=%s want=%s", tc.age, got, tc.want)
		}
		if got == "online" {
			t.Fatal("must not report online")
		}
	}
}
