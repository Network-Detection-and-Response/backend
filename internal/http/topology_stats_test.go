package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/config"
	"github.com/Network-Detection-and-Response/backend/internal/domain"
	httpapi "github.com/Network-Detection-and-Response/backend/internal/http"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	"github.com/Network-Detection-and-Response/backend/internal/service/stats"
	"github.com/Network-Detection-and-Response/backend/internal/service/topology"
	"github.com/google/uuid"
)

type topoStore struct {
	nodes []domain.Node
	edges []domain.Edge
	pairs []postgres.AttackEndpointPair
}

func (t *topoStore) TopologySnapshot(ctx context.Context, attackSince time.Time) ([]domain.Node, []domain.Edge, []postgres.AttackEndpointPair, error) {
	return t.nodes, t.edges, t.pairs, nil
}

type statsStore struct {
	out     postgres.OverviewStats
	buckets []postgres.MinuteBucket
}

func (s *statsStore) LoadOverviewStats(ctx context.Context, since time.Time) (postgres.OverviewStats, error) {
	return s.out, nil
}

func (s *statsStore) LoadMinuteBuckets(ctx context.Context, since, until time.Time) ([]postgres.MinuteBucket, error) {
	return s.buckets, nil
}

func topologyStatsRouter(topo *topoStore, st *statsStore) http.Handler {
	cfg := config.Config{
		SensorAPIKey:     "k",
		MaxBodyBytes:     1 << 20,
		MaxFlowsPerBatch: 100,
		AttackWindow:     15 * time.Minute,
	}
	return httpapi.NewRouter(httpapi.Dependencies{
		Config:          cfg,
		DB:              dbOK{},
		FlowEnqueuer:    &memQueue{},
		TopologyService: topology.NewService(topo, cfg.AttackWindow),
		StatsService:    stats.NewService(st),
	})
}

func TestTopologyEndpointShape(t *testing.T) {
	mac := "00:1A:2B:3C:4D:5E"
	srcID := domain.MakeNodeID(&mac, netip.MustParseAddr("192.168.1.50"))
	dstID := domain.MakeNodeID(nil, netip.MustParseAddr("10.0.0.5"))
	edgeID := uuid.New()
	r := topologyStatsRouter(&topoStore{
		nodes: []domain.Node{
			{ID: srcID, MACAddress: &mac, IPAddress: netip.MustParseAddr("192.168.1.50"), DeviceType: "unknown", LastSeen: time.Date(2026, 10, 9, 14, 30, 0, 0, time.UTC)},
			{ID: dstID, IPAddress: netip.MustParseAddr("10.0.0.5"), DeviceType: "unknown", LastSeen: time.Date(2026, 10, 9, 14, 30, 0, 0, time.UTC)},
		},
		edges: []domain.Edge{{
			ID: edgeID, SourceNodeID: srcID, TargetNodeID: dstID, Protocol: "TCP", TotalBytes: 35000,
			LastSeen: time.Date(2026, 10, 9, 14, 30, 0, 0, time.UTC),
		}},
		pairs: []postgres.AttackEndpointPair{{
			SrcIP: netip.MustParseAddr("192.168.1.50"), SrcMAC: &mac,
			DstIP: netip.MustParseAddr("10.0.0.5"),
		}},
	}, &statsStore{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/topology", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	data := body["data"].(map[string]any)
	nodes := data["nodes"].([]any)
	edges := data["edges"].([]any)
	if len(nodes) != 2 || len(edges) != 1 {
		t.Fatalf("nodes=%d edges=%d", len(nodes), len(edges))
	}
	edge := edges[0].(map[string]any)
	if edge["id"] != edgeID.String() || edge["is_under_attack"] != true {
		t.Fatalf("edge=%v", edge)
	}
	node0 := nodes[0].(map[string]any)
	for _, key := range []string{"id", "label", "ip", "device_type", "is_compromised", "last_seen"} {
		if _, ok := node0[key]; !ok {
			t.Fatalf("missing node field %s", key)
		}
	}
}

func TestStatsOverviewEndpoint(t *testing.T) {
	r := topologyStatsRouter(&topoStore{}, &statsStore{out: postgres.OverviewStats{
		FlowsTotal: 2, BytesTotal: 100, PacketsTotal: 10, IncidentsTotal: 1,
		IncidentsBySeverity: map[string]int64{
			"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 1,
		},
		Protocols: []postgres.ProtocolStat{{Protocol: "TCP", Flows: 2, Bytes: 100, Packets: 10}},
		TCPFlags:  postgres.TCPFlagTotals{SYN: 5, ACK: 40, RST: 1},
		Sensors: []postgres.SensorActivity{{
			SensorID:    "core_switch_mirror",
			LastBatchAt: time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC),
			FlowsLast5m: 2, Activity: "stale",
		}},
	}})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/overview?period=24h", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	data := body["data"].(map[string]any)
	if data["period"] != "24h" || data["flows_total"].(float64) != 2 {
		t.Fatalf("%v", data)
	}
	if _, ok := data["incidents_by_severity"].(map[string]any); !ok {
		t.Fatal("incidents_by_severity missing")
	}
	protocols := data["protocols"].([]any)
	if len(protocols) != 1 {
		t.Fatalf("protocols=%v", protocols)
	}
	flags := data["tcp_flags"].(map[string]any)
	if flags["syn"].(float64) != 5 || flags["ack"].(float64) != 40 || flags["rst"].(float64) != 1 {
		t.Fatalf("tcp_flags=%v", flags)
	}
	sensors := data["sensors"].([]any)
	if len(sensors) != 1 {
		t.Fatalf("sensors=%v", sensors)
	}
	s0 := sensors[0].(map[string]any)
	if s0["sensor_id"] != "core_switch_mirror" || s0["activity"] != "stale" {
		t.Fatalf("sensor=%v", s0)
	}
	if s0["activity"] == "online" {
		t.Fatal("must not report online")
	}
}

func TestStatsOverviewRejectsBadPeriod(t *testing.T) {
	r := topologyStatsRouter(&topoStore{}, &statsStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/overview?period=nope", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestStatsTimeseriesEndpoint(t *testing.T) {
	r := topologyStatsRouter(&topoStore{}, &statsStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/timeseries?period=1h", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	data := body["data"].(map[string]any)
	if data["period"] != "1h" || data["bucket"] != "1m" || data["timezone"] != "UTC" {
		t.Fatalf("%v", data)
	}
	points := data["points"].([]any)
	if len(points) != 60 {
		t.Fatalf("points=%d", len(points))
	}
	p0 := points[0].(map[string]any)
	for _, key := range []string{"t", "flows", "packets", "bytes"} {
		if _, ok := p0[key]; !ok {
			t.Fatalf("missing point field %s", key)
		}
	}
}

func TestStatsTimeseriesRejectsBadPeriod(t *testing.T) {
	r := topologyStatsRouter(&topoStore{}, &statsStore{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/timeseries?period=24h", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", w.Code)
	}
}
