package postgres_test

import (
	"context"
	"net/netip"
	"os/exec"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestStatsOverviewTCPFlagsSensorsAndTimeseries(t *testing.T) {
	if _, err := exec.LookPath("goose"); err != nil {
		t.Skip("goose CLI not installed")
	}

	ctx := context.Background()
	dbURL := testDatabaseURL(t)
	pool, err := postgres.Connect(ctx, dbURL)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer pool.Close()

	runGoose(t, dbURL, "up")
	store := postgres.NewStore(pool)

	now := time.Now().UTC().Truncate(time.Minute)
	batchID := uuid.New()
	sensorID := "stats_probe_" + uuid.NewString()[:8]

	flows := []domain.Flow{
		{
			ID: uuid.New(), BatchID: batchID, SensorID: sensorID,
			ObservedAt: now.Add(-2 * time.Minute),
			SrcIP:      netip.MustParseAddr("10.50.0.1"),
			DstIP:      netip.MustParseAddr("10.50.0.2"),
			SrcPort:    1234, DstPort: 443, Protocol: "TCP",
			DurationMs: 10, TotalPackets: 4, TotalBytes: 400,
			TCPFlags: domain.TCPFlags{SYN: 1, ACK: 3, RST: 0},
		},
		{
			ID: uuid.New(), BatchID: batchID, SensorID: sensorID,
			ObservedAt: now.Add(-2 * time.Minute).Add(5 * time.Second),
			SrcIP:      netip.MustParseAddr("10.50.0.3"),
			DstIP:      netip.MustParseAddr("10.50.0.4"),
			SrcPort:    0, DstPort: 0, Protocol: "ICMP",
			DurationMs: 1, TotalPackets: 2, TotalBytes: 128,
		},
		{
			ID: uuid.New(), BatchID: batchID, SensorID: sensorID,
			ObservedAt: now.Add(-40 * time.Minute),
			SrcIP:      netip.MustParseAddr("10.50.0.5"),
			DstIP:      netip.MustParseAddr("10.50.0.6"),
			SrcPort:    0, DstPort: 80, Protocol: "TCP",
			DurationMs: 100, TotalPackets: 100, TotalBytes: 1000,
			TCPFlags: domain.TCPFlags{SYN: 100, ACK: 0, RST: 1},
		},
	}

	err = store.WithinTx(ctx, func(tx pgx.Tx) error {
		return store.InsertFlows(ctx, tx, flows)
	})
	if err != nil {
		t.Fatalf("InsertFlows: %v", err)
	}

	ov, err := store.LoadOverviewStats(ctx, now.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("LoadOverviewStats: %v", err)
	}
	if ov.TCPFlags.SYN < 101 || ov.TCPFlags.ACK < 3 || ov.TCPFlags.RST < 1 {
		t.Fatalf("tcp_flags=%+v (want syn>=101 ack>=3 rst>=1)", ov.TCPFlags)
	}

	var foundSensor bool
	for _, sa := range ov.Sensors {
		if sa.SensorID == sensorID {
			foundSensor = true
			if sa.FlowsLast5m < 2 {
				t.Fatalf("flows_last_5m=%d", sa.FlowsLast5m)
			}
			if sa.Activity == "online" {
				t.Fatal("must not report online")
			}
			if sa.Activity != "active" && sa.Activity != "idle" {
				// last batch at -2m → active
				t.Fatalf("activity=%s last=%v", sa.Activity, sa.LastBatchAt)
			}
			break
		}
	}
	if !foundSensor {
		t.Fatalf("sensor %s missing in %+v", sensorID, ov.Sensors)
	}

	since := now.Add(-60 * time.Minute)
	until := now.Add(time.Minute)
	buckets, err := store.LoadMinuteBuckets(ctx, since, until)
	if err != nil {
		t.Fatalf("LoadMinuteBuckets: %v", err)
	}
	var hitRecent, hitOld bool
	for _, b := range buckets {
		m := b.Minute.UTC()
		if m.Equal(now.Add(-2 * time.Minute)) {
			hitRecent = true
			if b.Flows < 2 || b.Packets < 6 || b.Bytes < 528 {
				t.Fatalf("recent bucket=%+v", b)
			}
		}
		if m.Equal(now.Add(-40 * time.Minute)) {
			hitOld = true
			if b.Flows < 1 {
				t.Fatalf("old bucket=%+v", b)
			}
		}
	}
	if !hitRecent || !hitOld {
		t.Fatalf("buckets incomplete recent=%v old=%v all=%+v", hitRecent, hitOld, buckets)
	}
}
