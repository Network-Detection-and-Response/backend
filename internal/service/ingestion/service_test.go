package ingestion

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/agent"
	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/integrations/ml"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type mockStore struct {
	failInsert      bool
	failIncident    bool
	idempotentFlows bool
	flows           []domain.Flow
	nodes           []domain.Node
	edges           []domain.Edge
	incidents       []domain.Incident
	insertFlowCalls int
	insertIncCalls  int
}

func (m *mockStore) WithinTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return fn(nil)
}

func (m *mockStore) InsertFlows(ctx context.Context, tx pgx.Tx, flows []domain.Flow) error {
	m.insertFlowCalls++
	if m.failInsert {
		return errors.New("insert failed")
	}
	if m.idempotentFlows {
		existing := make(map[uuid.UUID]struct{}, len(m.flows))
		for _, f := range m.flows {
			existing[f.ID] = struct{}{}
		}
		for _, f := range flows {
			if _, ok := existing[f.ID]; ok {
				continue
			}
			m.flows = append(m.flows, f)
			existing[f.ID] = struct{}{}
		}
		return nil
	}
	m.flows = append(m.flows, flows...)
	return nil
}

func (m *mockStore) UpsertNode(ctx context.Context, tx pgx.Tx, node domain.Node) error {
	m.nodes = append(m.nodes, node)
	return nil
}

func (m *mockStore) UpsertEdge(ctx context.Context, tx pgx.Tx, edge domain.Edge) error {
	m.edges = append(m.edges, edge)
	return nil
}

func (m *mockStore) ListEnabledWhitelistSchedules(ctx context.Context) ([]domain.WhitelistSchedule, error) {
	return nil, nil
}

func (m *mockStore) CountRecentFlowsBySrcIP(ctx context.Context, srcIP netip.Addr, since time.Time) (int64, error) {
	return 1, nil
}

func (m *mockStore) HasIncidentForFlowID(ctx context.Context, flowID uuid.UUID) (bool, error) {
	for _, inc := range m.incidents {
		if inc.FlowID != nil && *inc.FlowID == flowID {
			return true, nil
		}
	}
	return false, nil
}

func (m *mockStore) InsertIncident(ctx context.Context, tx pgx.Tx, inc domain.Incident) error {
	m.insertIncCalls++
	if m.failIncident {
		return errors.New("incident insert failed")
	}
	m.incidents = append(m.incidents, inc)
	return nil
}

type mockPredictor struct {
	configured bool
	preds      []ml.Prediction
	err        error
	calls      int
}

func (p *mockPredictor) Configured() bool { return p.configured }

func (p *mockPredictor) Predict(ctx context.Context, flows []domain.Flow) ([]ml.Prediction, error) {
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	return p.preds, nil
}

func TestServiceProcessBatchPersistsTopology(t *testing.T) {
	store := &mockStore{}
	svc := NewService(store, Options{})
	now := time.Date(2026, 10, 9, 14, 30, 0, 0, time.UTC)
	srcMAC := "00:1A:2B:3C:4D:5E"
	job := BatchJob{
		BatchID:    uuid.New(),
		SensorID:   "s1",
		ObservedAt: now,
		Flows: []domain.Flow{{
			ID: uuid.New(), BatchID: uuid.New(), SensorID: "s1", ObservedAt: now,
			SrcIP: netip.MustParseAddr("192.168.1.50"), SrcMAC: &srcMAC,
			DstIP: netip.MustParseAddr("10.0.0.5"), DstMAC: nil,
			SrcPort: 1, DstPort: 80, Protocol: "TCP",
			TotalPackets: 2, TotalBytes: 100,
		}},
	}
	if err := svc.ProcessBatch(context.Background(), job); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if len(store.flows) != 1 {
		t.Fatalf("flows=%d", len(store.flows))
	}
	if len(store.nodes) != 2 {
		t.Fatalf("nodes=%d want 2 (mac + ip-only)", len(store.nodes))
	}
	if len(store.edges) != 1 {
		t.Fatalf("edges=%d", len(store.edges))
	}
	foundIPOnly := false
	for _, n := range store.nodes {
		if n.ID == "ip:10.0.0.5" {
			foundIPOnly = true
		}
	}
	if !foundIPOnly {
		t.Fatal("expected IP-based node id for null dst MAC")
	}
}

func TestServiceProcessBatchPropagatesDBError(t *testing.T) {
	store := &mockStore{failInsert: true}
	svc := NewService(store, Options{})
	err := svc.ProcessBatch(context.Background(), BatchJob{
		Flows: []domain.Flow{{
			ID: uuid.New(), SrcIP: netip.MustParseAddr("1.1.1.1"), DstIP: netip.MustParseAddr("2.2.2.2"),
			Protocol: "UDP", ObservedAt: time.Now().UTC(),
		}},
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestServiceMLFailureKeepsFlowsAndNoIncident(t *testing.T) {
	store := &mockStore{}
	pred := &mockPredictor{configured: true, err: errors.New("ml down")}
	svc := NewService(store, Options{
		Predictor:     pred,
		DecisionStore: store,
		Agent:         agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil),
	})
	flowID := uuid.New()
	job := BatchJob{
		BatchID: uuid.New(), SensorID: "s1", ObservedAt: time.Now().UTC(),
		Flows: []domain.Flow{{
			ID: flowID, SrcIP: netip.MustParseAddr("1.1.1.1"), DstIP: netip.MustParseAddr("2.2.2.2"),
			Protocol: "TCP", ObservedAt: time.Now().UTC(),
		}},
	}
	if err := svc.ProcessBatch(context.Background(), job); err != nil {
		t.Fatalf("ProcessBatch must succeed after persist: %v", err)
	}
	if len(store.flows) != 1 {
		t.Fatalf("flows must remain saved, got %d", len(store.flows))
	}
	if len(store.incidents) != 0 {
		t.Fatalf("must not fabricate incidents, got %d", len(store.incidents))
	}
	if svc.MLFailures() != 1 {
		t.Fatalf("mlFailures=%d", svc.MLFailures())
	}
}

func TestServiceCreatesIncidentFromML(t *testing.T) {
	store := &mockStore{}
	flowID := uuid.New()
	pred := &mockPredictor{
		configured: true,
		preds: []ml.Prediction{{
			FlowID: flowID,
			Probabilities: map[string]float64{
				"Normal": 0.20, "PortScan": 0.60, "DDoS": 0.10, "BruteForce": 0.10,
			},
		}},
	}
	svc := NewService(store, Options{
		Predictor:     pred,
		DecisionStore: store,
		Agent:         agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil),
	})
	job := BatchJob{
		BatchID: uuid.New(), SensorID: "s1", ObservedAt: time.Now().UTC(),
		Flows: []domain.Flow{{
			ID: flowID, SrcIP: netip.MustParseAddr("192.168.1.50"), DstIP: netip.MustParseAddr("10.0.0.5"),
			Protocol: "TCP", ObservedAt: time.Now().UTC(),
		}},
	}
	if err := svc.ProcessBatch(context.Background(), job); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if len(store.incidents) != 1 {
		t.Fatalf("incidents=%d", len(store.incidents))
	}
	if store.incidents[0].AttackClass != domain.AttackPortScan {
		t.Fatalf("class=%s", store.incidents[0].AttackClass)
	}
}

func TestServiceDBFailureDoesNotCallML(t *testing.T) {
	store := &mockStore{failInsert: true}
	pred := &mockPredictor{configured: true}
	svc := NewService(store, Options{
		Predictor:     pred,
		DecisionStore: store,
		Agent:         agent.New(agent.Config{AttackThreshold: 0.60}, nil),
	})
	err := svc.ProcessBatch(context.Background(), BatchJob{
		Flows: []domain.Flow{{
			ID: uuid.New(), SrcIP: netip.MustParseAddr("1.1.1.1"), DstIP: netip.MustParseAddr("2.2.2.2"),
			Protocol: "TCP", ObservedAt: time.Now().UTC(),
		}},
	})
	if err == nil {
		t.Fatal("expected persist error")
	}
	if pred.calls != 0 {
		t.Fatalf("ML must not run before successful persist, calls=%d", pred.calls)
	}
}

func TestServiceIncidentInsertFailureDoesNotFailBatchOrReplayFlows(t *testing.T) {
	store := &mockStore{failIncident: true}
	flowID := uuid.New()
	pred := &mockPredictor{
		configured: true,
		preds: []ml.Prediction{{
			FlowID: flowID,
			Probabilities: map[string]float64{
				"Normal": 0.20, "PortScan": 0.60, "DDoS": 0.10, "BruteForce": 0.10,
			},
		}},
	}
	svc := NewService(store, Options{
		Predictor:     pred,
		DecisionStore: store,
		Agent:         agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil),
	})
	job := BatchJob{
		BatchID: uuid.New(),
		Flows: []domain.Flow{{
			ID: flowID, SrcIP: netip.MustParseAddr("192.168.1.50"), DstIP: netip.MustParseAddr("10.0.0.5"),
			Protocol: "TCP", ObservedAt: time.Now().UTC(),
		}},
	}
	if err := svc.ProcessBatch(context.Background(), job); err != nil {
		t.Fatalf("incident failure must not fail ProcessBatch: %v", err)
	}
	if len(store.flows) != 1 {
		t.Fatalf("flows=%d", len(store.flows))
	}
	if store.insertFlowCalls != 1 {
		t.Fatalf("insertFlowCalls=%d want 1 (no retry of flows)", store.insertFlowCalls)
	}
	if svc.IncidentFailures() != 1 {
		t.Fatalf("incidentFails=%d", svc.IncidentFailures())
	}
}

func TestServiceReprocessDoesNotDuplicateIncidents(t *testing.T) {
	store := &mockStore{idempotentFlows: true}
	flowID := uuid.New()
	pred := &mockPredictor{
		configured: true,
		preds: []ml.Prediction{{
			FlowID: flowID,
			Probabilities: map[string]float64{
				"Normal": 0.20, "PortScan": 0.60, "DDoS": 0.10, "BruteForce": 0.10,
			},
		}},
	}
	svc := NewService(store, Options{
		Predictor:     pred,
		DecisionStore: store,
		Agent:         agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil),
	})
	job := BatchJob{
		BatchID: uuid.New(),
		Flows: []domain.Flow{{
			ID: flowID, SrcIP: netip.MustParseAddr("192.168.1.50"), DstIP: netip.MustParseAddr("10.0.0.5"),
			Protocol: "TCP", ObservedAt: time.Now().UTC(),
		}},
	}
	if err := svc.ProcessBatch(context.Background(), job); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := svc.ProcessBatch(context.Background(), job); err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(store.flows) != 1 {
		t.Fatalf("flows=%d", len(store.flows))
	}
	if len(store.incidents) != 1 {
		t.Fatalf("incidents=%d want 1 (no duplicates)", len(store.incidents))
	}
	if store.insertIncCalls != 1 {
		t.Fatalf("insertIncCalls=%d want 1", store.insertIncCalls)
	}
}

func TestServiceMLOutageDoesNotBlockNextBatch(t *testing.T) {
	store := &mockStore{}
	failing := &mockPredictor{configured: true, err: errors.New("ml down")}
	svc := NewService(store, Options{
		Predictor:     failing,
		DecisionStore: store,
		Agent:         agent.New(agent.Config{AttackThreshold: 0.60, DDoSCriticalThreshold: 0.85}, nil),
	})
	job1 := BatchJob{
		BatchID: uuid.New(),
		Flows: []domain.Flow{{
			ID: uuid.New(), SrcIP: netip.MustParseAddr("1.1.1.1"), DstIP: netip.MustParseAddr("2.2.2.2"),
			Protocol: "TCP", ObservedAt: time.Now().UTC(),
		}},
	}
	if err := svc.ProcessBatch(context.Background(), job1); err != nil {
		t.Fatalf("batch1: %v", err)
	}

	okFlow := uuid.New()
	svc.predictor = &mockPredictor{
		configured: true,
		preds: []ml.Prediction{{
			FlowID: okFlow,
			Probabilities: map[string]float64{
				"Normal": 0.20, "PortScan": 0.60, "DDoS": 0.10, "BruteForce": 0.10,
			},
		}},
	}
	job2 := BatchJob{
		BatchID: uuid.New(),
		Flows: []domain.Flow{{
			ID: okFlow, SrcIP: netip.MustParseAddr("3.3.3.3"), DstIP: netip.MustParseAddr("4.4.4.4"),
			Protocol: "TCP", ObservedAt: time.Now().UTC(),
		}},
	}
	if err := svc.ProcessBatch(context.Background(), job2); err != nil {
		t.Fatalf("batch2: %v", err)
	}
	if len(store.flows) != 2 {
		t.Fatalf("flows=%d", len(store.flows))
	}
	if len(store.incidents) != 1 {
		t.Fatalf("incidents=%d", len(store.incidents))
	}
}
