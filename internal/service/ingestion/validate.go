package ingestion

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/google/uuid"
)

// BatchRequest is the sensor POST /api/v1/flows body.
// Unknown JSON fields are rejected (DisallowUnknownFields).
type BatchRequest struct {
	SensorID  string        `json:"sensor_id"`
	Timestamp string        `json:"timestamp"`
	Flows     []FlowRequest `json:"flows"`
}

// FlowRequest is one flow object from the sensor batch.
type FlowRequest struct {
	SrcIP        string           `json:"src_ip"`
	SrcMAC       *string          `json:"src_mac"`
	DstIP        string           `json:"dst_ip"`
	DstMAC       *string          `json:"dst_mac"`
	SrcPort      int              `json:"src_port"`
	DstPort      int              `json:"dst_port"`
	Protocol     string           `json:"protocol"`
	DurationMs   int64            `json:"duration_ms"`
	TotalPackets int64            `json:"total_packets"`
	TotalBytes   int64            `json:"total_bytes"`
	TCPFlags     *TCPFlagsRequest `json:"tcp_flags"`
}

// TCPFlagsRequest holds optional TCP flag counters.
type TCPFlagsRequest struct {
	SYN int64 `json:"syn"`
	ACK int64 `json:"ack"`
	RST int64 `json:"rst"`
}

// ValidationError is a client-facing validation failure.
type ValidationError struct {
	Message string
	Code    string // VALIDATION_ERROR or PAYLOAD_TOO_LARGE
}

func (e *ValidationError) Error() string {
	return e.Message
}

// DecodeAndValidate parses JSON strictly and validates against API_CONTRACTS.md.
// maxFlows triggers PAYLOAD_TOO_LARGE when exceeded.
func DecodeAndValidate(raw []byte, maxFlows int) (BatchJob, error) {
	if len(raw) == 0 {
		return BatchJob{}, &ValidationError{Code: "VALIDATION_ERROR", Message: "request body is required"}
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var req BatchRequest
	if err := dec.Decode(&req); err != nil {
		return BatchJob{}, &ValidationError{
			Code:    "VALIDATION_ERROR",
			Message: fmt.Sprintf("invalid JSON: %v", err),
		}
	}
	// Reject trailing junk after the first JSON value.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return BatchJob{}, &ValidationError{
			Code:    "VALIDATION_ERROR",
			Message: "request body must contain a single JSON object",
		}
	}

	return ValidateBatch(req, maxFlows)
}

// ValidateBatch checks field constraints and builds a BatchJob with generated IDs.
func ValidateBatch(req BatchRequest, maxFlows int) (BatchJob, error) {
	sensorID := strings.TrimSpace(req.SensorID)
	if sensorID == "" {
		return BatchJob{}, &ValidationError{Code: "VALIDATION_ERROR", Message: "sensor_id is required"}
	}

	observedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(req.Timestamp))
	if err != nil {
		return BatchJob{}, &ValidationError{
			Code:    "VALIDATION_ERROR",
			Message: "timestamp must be RFC3339 UTC, e.g. 2026-10-09T14:30:00Z",
		}
	}
	observedAt = observedAt.UTC()

	if len(req.Flows) == 0 {
		return BatchJob{}, &ValidationError{Code: "VALIDATION_ERROR", Message: "flows must not be empty"}
	}
	if maxFlows > 0 && len(req.Flows) > maxFlows {
		return BatchJob{}, &ValidationError{
			Code:    "PAYLOAD_TOO_LARGE",
			Message: fmt.Sprintf("flows batch exceeds limit of %d", maxFlows),
		}
	}

	batchID := uuid.New()
	flows := make([]domain.Flow, 0, len(req.Flows))
	for i, fr := range req.Flows {
		f, err := validateFlow(fr, i, batchID, sensorID, observedAt)
		if err != nil {
			return BatchJob{}, err
		}
		flows = append(flows, f)
	}

	return BatchJob{
		BatchID:    batchID,
		SensorID:   sensorID,
		ObservedAt: observedAt,
		Flows:      flows,
	}, nil
}

func validateFlow(fr FlowRequest, index int, batchID uuid.UUID, sensorID string, observedAt time.Time) (domain.Flow, error) {
	prefix := fmt.Sprintf("flows[%d]", index)

	srcIP, err := netip.ParseAddr(strings.TrimSpace(fr.SrcIP))
	if err != nil {
		return domain.Flow{}, &ValidationError{
			Code:    "VALIDATION_ERROR",
			Message: fmt.Sprintf("%s.src_ip must be a valid IPv4/IPv6 address", prefix),
		}
	}
	dstIP, err := netip.ParseAddr(strings.TrimSpace(fr.DstIP))
	if err != nil {
		return domain.Flow{}, &ValidationError{
			Code:    "VALIDATION_ERROR",
			Message: fmt.Sprintf("%s.dst_ip must be a valid IPv4/IPv6 address", prefix),
		}
	}

	srcMAC, err := optionalMAC(fr.SrcMAC, prefix+".src_mac")
	if err != nil {
		return domain.Flow{}, err
	}
	dstMAC, err := optionalMAC(fr.DstMAC, prefix+".dst_mac")
	if err != nil {
		return domain.Flow{}, err
	}

	if err := validatePort(fr.SrcPort, prefix+".src_port"); err != nil {
		return domain.Flow{}, err
	}
	if err := validatePort(fr.DstPort, prefix+".dst_port"); err != nil {
		return domain.Flow{}, err
	}

	protocol := strings.ToUpper(strings.TrimSpace(fr.Protocol))
	if protocol == "" {
		return domain.Flow{}, &ValidationError{
			Code:    "VALIDATION_ERROR",
			Message: fmt.Sprintf("%s.protocol is required", prefix),
		}
	}

	if fr.DurationMs < 0 {
		return domain.Flow{}, &ValidationError{
			Code:    "VALIDATION_ERROR",
			Message: fmt.Sprintf("%s.duration_ms must be >= 0", prefix),
		}
	}
	if fr.TotalPackets < 0 {
		return domain.Flow{}, &ValidationError{
			Code:    "VALIDATION_ERROR",
			Message: fmt.Sprintf("%s.total_packets must be >= 0", prefix),
		}
	}
	if fr.TotalBytes < 0 {
		return domain.Flow{}, &ValidationError{
			Code:    "VALIDATION_ERROR",
			Message: fmt.Sprintf("%s.total_bytes must be >= 0", prefix),
		}
	}

	flags := domain.TCPFlags{}
	if fr.TCPFlags != nil {
		if fr.TCPFlags.SYN < 0 || fr.TCPFlags.ACK < 0 || fr.TCPFlags.RST < 0 {
			return domain.Flow{}, &ValidationError{
				Code:    "VALIDATION_ERROR",
				Message: fmt.Sprintf("%s.tcp_flags counters must be >= 0", prefix),
			}
		}
		flags = domain.TCPFlags{SYN: fr.TCPFlags.SYN, ACK: fr.TCPFlags.ACK, RST: fr.TCPFlags.RST}
	}

	return domain.Flow{
		ID:           uuid.New(),
		BatchID:      batchID,
		SensorID:     sensorID,
		ObservedAt:   observedAt,
		SrcIP:        srcIP,
		SrcMAC:       srcMAC,
		DstIP:        dstIP,
		DstMAC:       dstMAC,
		SrcPort:      fr.SrcPort,
		DstPort:      fr.DstPort,
		Protocol:     protocol,
		DurationMs:   fr.DurationMs,
		TotalPackets: fr.TotalPackets,
		TotalBytes:   fr.TotalBytes,
		TCPFlags:     flags,
	}, nil
}

func optionalMAC(raw *string, field string) (*string, error) {
	if raw == nil {
		return nil, nil
	}
	trimmed := strings.TrimSpace(*raw)
	if trimmed == "" {
		// Empty string treated as absent MAC (same as null).
		return nil, nil
	}
	normalized, ok := domain.NormalizeMAC(trimmed)
	if !ok {
		return nil, &ValidationError{
			Code:    "VALIDATION_ERROR",
			Message: fmt.Sprintf("%s must be AA:BB:CC:DD:EE:FF or null", field),
		}
	}
	return &normalized, nil
}

func validatePort(port int, field string) error {
	// API_CONTRACTS: ports are 1..65535 for this course version.
	if port < 1 || port > 65535 {
		return &ValidationError{
			Code:    "VALIDATION_ERROR",
			Message: fmt.Sprintf("%s must be in range 1..65535", field),
		}
	}
	return nil
}
