package realtime

import (
	"encoding/json"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/google/uuid"
)

// Documented WebSocket event types (API_CONTRACTS.md).
const (
	TypeFlowStats       = "FLOW_STATS"
	TypeIncidentAlert   = "INCIDENT_ALERT"
	TypeTopologyUpdated = "TOPOLOGY_UPDATED"
)

// Event is the JSON envelope sent to dashboard clients.
type Event struct {
	Type      string          `json:"type"`
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

// NewEvent builds an envelope with UTC RFC3339-serializable timestamp.
func NewEvent(typ string, data any) (Event, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return Event{}, err
	}
	return Event{
		Type:      typ,
		Timestamp: time.Now().UTC(),
		Data:      raw,
	}, nil
}

// FlowStatsData is published after a batch is persisted.
type FlowStatsData struct {
	BatchID       string `json:"batch_id"`
	AcceptedFlows int    `json:"accepted_flows"`
	BytesTotal    int64  `json:"bytes_total"`
	PacketsTotal  int64  `json:"packets_total"`
}

// TopologyUpdatedData is published after nodes/edges are upserted from a batch.
type TopologyUpdatedData struct {
	BatchID       string `json:"batch_id"`
	NodesUpserted int    `json:"nodes_upserted"`
	EdgesUpserted int    `json:"edges_upserted"`
}

// IncidentAlertData matches the documented INCIDENT_ALERT payload.
type IncidentAlertData struct {
	IncidentID  string `json:"incident_id"`
	Severity    string `json:"severity"`
	AttackClass string `json:"attack_class,omitempty"`
	Status      string `json:"status,omitempty"`
}

// FlowStatsEvent builds a FLOW_STATS event from batch aggregates.
func FlowStatsEvent(batchID uuid.UUID, flows []domain.Flow) (Event, error) {
	var bytes, packets int64
	for _, f := range flows {
		bytes += f.TotalBytes
		packets += f.TotalPackets
	}
	return NewEvent(TypeFlowStats, FlowStatsData{
		BatchID:       batchID.String(),
		AcceptedFlows: len(flows),
		BytesTotal:    bytes,
		PacketsTotal:  packets,
	})
}

// TopologyUpdatedEvent builds a TOPOLOGY_UPDATED event.
func TopologyUpdatedEvent(batchID uuid.UUID, nodes, edges int) (Event, error) {
	return NewEvent(TypeTopologyUpdated, TopologyUpdatedData{
		BatchID:       batchID.String(),
		NodesUpserted: nodes,
		EdgesUpserted: edges,
	})
}

// IncidentAlertEvent builds an INCIDENT_ALERT event.
func IncidentAlertEvent(inc domain.Incident) (Event, error) {
	return NewEvent(TypeIncidentAlert, IncidentAlertData{
		IncidentID:  inc.ID.String(),
		Severity:    inc.Severity,
		AttackClass: inc.AttackClass,
		Status:      inc.Status,
	})
}
