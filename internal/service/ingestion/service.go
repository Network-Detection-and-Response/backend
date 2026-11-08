package ingestion

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/agent"
	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/integrations/ml"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// BatchStore is the persistence surface used by the ingestion processor.
type BatchStore interface {
	WithinTx(ctx context.Context, fn func(tx pgx.Tx) error) error
	InsertFlows(ctx context.Context, tx pgx.Tx, flows []domain.Flow) error
	UpsertNode(ctx context.Context, tx pgx.Tx, node domain.Node) error
	UpsertEdge(ctx context.Context, tx pgx.Tx, edge domain.Edge) error
}

// Predictor calls the ML service. Optional; nil skips prediction.
type Predictor interface {
	Configured() bool
	Predict(ctx context.Context, flows []domain.Flow) ([]ml.Prediction, error)
}

// DecisionStore loads whitelist/history and persists incidents after ML.
type DecisionStore interface {
	ListEnabledWhitelistSchedules(ctx context.Context) ([]domain.WhitelistSchedule, error)
	CountRecentFlowsBySrcIP(ctx context.Context, srcIP netip.Addr, since time.Time) (int64, error)
	HasIncidentForFlowID(ctx context.Context, flowID uuid.UUID) (bool, error)
	InsertIncident(ctx context.Context, tx pgx.Tx, inc domain.Incident) error
}

// Service persists accepted batches, then optionally scores them with ML and
// creates incidents via the Decision Agent. ML/incident failures never roll
// back already saved telemetry and do not fail ProcessBatch (avoids duplicate
// flow inserts on queue retry).
type Service struct {
	store         BatchStore
	predictor     Predictor
	decisions     DecisionStore
	agent         *agent.Agent
	log           *slog.Logger
	historyWindow time.Duration
	mlFailures    atomic.Int64
	incidentFails atomic.Int64
}

// Options configures optional ML / decision wiring.
type Options struct {
	Predictor     Predictor
	DecisionStore DecisionStore
	Agent         *agent.Agent
	Log           *slog.Logger
	HistoryWindow time.Duration
}

// NewService constructs an ingestion processor. opts may be empty for persist-only mode.
func NewService(store BatchStore, opts Options) *Service {
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	window := opts.HistoryWindow
	if window <= 0 {
		window = 15 * time.Minute
	}
	return &Service{
		store:         store,
		predictor:     opts.Predictor,
		decisions:     opts.DecisionStore,
		agent:         opts.Agent,
		log:           log,
		historyWindow: window,
	}
}

// MLFailures returns how many batches failed ML scoring after a successful persist.
func (s *Service) MLFailures() int64 { return s.mlFailures.Load() }

// IncidentFailures returns how many incident inserts failed after ML.
func (s *Service) IncidentFailures() int64 { return s.incidentFails.Load() }

// ProcessBatch inserts all flows and upserts observed nodes/edges in one transaction.
// After a successful commit it calls ML (if configured) and may create incidents.
func (s *Service) ProcessBatch(ctx context.Context, job BatchJob) error {
	if len(job.Flows) == 0 {
		return nil
	}

	nodes, edges := aggregateTopology(job)

	if err := s.store.WithinTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.InsertFlows(ctx, tx, job.Flows); err != nil {
			return fmt.Errorf("insert flows: %w", err)
		}
		for _, n := range nodes {
			if err := s.store.UpsertNode(ctx, tx, n); err != nil {
				return err
			}
		}
		for _, e := range edges {
			if err := s.store.UpsertEdge(ctx, tx, e); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	s.scoreAndDecide(ctx, job)
	return nil
}

func (s *Service) scoreAndDecide(ctx context.Context, job BatchJob) {
	if s.predictor == nil || !s.predictor.Configured() || s.agent == nil || s.decisions == nil {
		return
	}

	preds, err := s.predictor.Predict(ctx, job.Flows)
	if err != nil {
		s.mlFailures.Add(1)
		s.log.Error("ml_predict_failed",
			"batch_id", job.BatchID.String(),
			"sensor_id", job.SensorID,
			"flows", len(job.Flows),
			"error", err.Error(),
		)
		return
	}

	schedules, err := s.decisions.ListEnabledWhitelistSchedules(ctx)
	if err != nil {
		s.log.Error("whitelist_load_failed",
			"batch_id", job.BatchID.String(),
			"error", err.Error(),
		)
		schedules = nil
	}

	byID := make(map[uuid.UUID]domain.Flow, len(job.Flows))
	for _, f := range job.Flows {
		byID[f.ID] = f
	}

	for _, p := range preds {
		flow, ok := byID[p.FlowID]
		if !ok {
			s.log.Error("ml_prediction_unknown_flow",
				"batch_id", job.BatchID.String(),
				"flow_id", p.FlowID.String(),
			)
			continue
		}

		agentCtx := agent.Context{
			ObservedAt:          flow.ObservedAt,
			Schedules:           schedules,
			RecentSrcFlowWindow: s.historyWindow,
		}
		if count, err := s.decisions.CountRecentFlowsBySrcIP(ctx, flow.SrcIP, flow.ObservedAt.Add(-s.historyWindow)); err == nil {
			agentCtx.RecentSrcFlowCount = count
		}

		verdict, err := s.agent.EvaluateFlow(flow, p.Probabilities, agentCtx)
		if err != nil {
			s.log.Error("decision_agent_failed",
				"batch_id", job.BatchID.String(),
				"flow_id", flow.ID.String(),
				"error", err.Error(),
			)
			continue
		}
		if verdict == nil {
			continue
		}

		exists, err := s.decisions.HasIncidentForFlowID(ctx, flow.ID)
		if err != nil {
			s.log.Error("incident_dedup_check_failed",
				"batch_id", job.BatchID.String(),
				"flow_id", flow.ID.String(),
				"error", err.Error(),
			)
		} else if exists {
			s.log.Info("incident_skip_duplicate",
				"batch_id", job.BatchID.String(),
				"flow_id", flow.ID.String(),
			)
			continue
		}

		inc := verdict.ToIncident(flow)
		if err := s.decisions.InsertIncident(ctx, nil, inc); err != nil {
			s.incidentFails.Add(1)
			s.log.Error("incident_insert_failed",
				"batch_id", job.BatchID.String(),
				"flow_id", flow.ID.String(),
				"error", err.Error(),
			)
			continue
		}
		s.log.Info("incident_created",
			"batch_id", job.BatchID.String(),
			"flow_id", flow.ID.String(),
			"incident_id", inc.ID.String(),
			"attack_class", inc.AttackClass,
			"severity", inc.Severity,
			"status", inc.Status,
		)
	}
}

func aggregateTopology(job BatchJob) ([]domain.Node, []domain.Edge) {
	nodeMap := make(map[string]domain.Node)
	type edgeKey struct {
		src, dst, proto string
	}
	edgeMap := make(map[edgeKey]domain.Edge)

	for _, f := range job.Flows {
		srcID := domain.MakeNodeID(f.SrcMAC, f.SrcIP)
		dstID := domain.MakeNodeID(f.DstMAC, f.DstIP)

		upsertNodeLocal(nodeMap, domain.Node{
			ID:         srcID,
			MACAddress: f.SrcMAC,
			IPAddress:  f.SrcIP,
			DeviceType: "unknown",
			FirstSeen:  f.ObservedAt,
			LastSeen:   f.ObservedAt,
		})
		upsertNodeLocal(nodeMap, domain.Node{
			ID:         dstID,
			MACAddress: f.DstMAC,
			IPAddress:  f.DstIP,
			DeviceType: "unknown",
			FirstSeen:  f.ObservedAt,
			LastSeen:   f.ObservedAt,
		})

		k := edgeKey{src: srcID, dst: dstID, proto: f.Protocol}
		if existing, ok := edgeMap[k]; ok {
			existing.TotalBytes += f.TotalBytes
			existing.TotalPackets += f.TotalPackets
			if f.ObservedAt.After(existing.LastSeen) {
				existing.LastSeen = f.ObservedAt
			}
			edgeMap[k] = existing
		} else {
			edgeMap[k] = domain.Edge{
				ID:           uuid.New(),
				SourceNodeID: srcID,
				TargetNodeID: dstID,
				Protocol:     f.Protocol,
				TotalBytes:   f.TotalBytes,
				TotalPackets: f.TotalPackets,
				LastSeen:     f.ObservedAt,
			}
		}
	}

	nodes := make([]domain.Node, 0, len(nodeMap))
	for _, n := range nodeMap {
		nodes = append(nodes, n)
	}
	edges := make([]domain.Edge, 0, len(edgeMap))
	for _, e := range edgeMap {
		edges = append(edges, e)
	}
	return nodes, edges
}

func upsertNodeLocal(m map[string]domain.Node, n domain.Node) {
	if prev, ok := m[n.ID]; ok {
		if n.LastSeen.After(prev.LastSeen) {
			prev.LastSeen = n.LastSeen
			prev.IPAddress = n.IPAddress
			if n.MACAddress != nil {
				prev.MACAddress = n.MACAddress
			}
		}
		if n.FirstSeen.Before(prev.FirstSeen) {
			prev.FirstSeen = n.FirstSeen
		}
		m[n.ID] = prev
		return
	}
	m[n.ID] = n
}
