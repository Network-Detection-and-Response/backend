package ml

import (
	"math"

	"github.com/google/uuid"
)

// Required class labels from API_CONTRACTS.md.
var RequiredClasses = []string{"Normal", "PortScan", "DDoS", "BruteForce"}

// ProbabilitySumTolerance is the allowed |sum(probabilities)-1| margin.
const ProbabilitySumTolerance = 0.02

// FlowFeatures is one flow sent to the ML service.
type FlowFeatures struct {
	FlowID       string           `json:"flow_id"`
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
	TCPFlags     map[string]int64 `json:"tcp_flags"`
}

// PredictRequest is POST ${ML_SERVICE_URL}/predict body.
type PredictRequest struct {
	Flows []FlowFeatures `json:"flows"`
}

// Prediction is one ML result keyed by flow_id.
type Prediction struct {
	FlowID        uuid.UUID
	Probabilities map[string]float64
}

// PredictResponse is the ML JSON envelope.
type PredictResponse struct {
	Predictions []struct {
		FlowID        string             `json:"flow_id"`
		Probabilities map[string]float64 `json:"probabilities"`
	} `json:"predictions"`
}

// ValidateProbabilities checks finite values in [0,1], required classes, and sum ≈ 1.
func ValidateProbabilities(p map[string]float64) error {
	if p == nil {
		return ErrInvalidProbabilities
	}
	var sum float64
	for _, class := range RequiredClasses {
		v, ok := p[class]
		if !ok {
			return ErrInvalidProbabilities
		}
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 {
			return ErrInvalidProbabilities
		}
		sum += v
	}
	if math.Abs(sum-1.0) > ProbabilitySumTolerance {
		return ErrInvalidProbabilities
	}
	return nil
}
