package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/google/uuid"
)

// Client calls POST ${baseURL}/predict with an explicit timeout.
// It does not send secrets. When baseURL is empty, Predict returns ErrNotConfigured.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient builds an ML HTTP client. timeout covers the whole request including connect.
// Empty baseURL is allowed: Predict then returns ErrNotConfigured without a network call.
func NewClient(baseURL string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Configured reports whether a base URL is set.
func (c *Client) Configured() bool {
	return c != nil && c.baseURL != ""
}

// Predict sends persisted flows to the ML service and validates the response.
// It never fabricates predictions on error.
func (c *Client) Predict(ctx context.Context, flows []domain.Flow) ([]Prediction, error) {
	if !c.Configured() {
		return nil, ErrNotConfigured
	}
	if len(flows) == 0 {
		return nil, nil
	}

	reqBody := PredictRequest{Flows: make([]FlowFeatures, 0, len(flows))}
	for _, f := range flows {
		reqBody.Flows = append(reqBody.Flows, flowToFeatures(f))
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal request: %v", ErrInvalidResponse, err)
	}

	url := c.baseURL + "/predict"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create ml request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ml predict request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrInvalidResponse, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: status=%d", ErrHTTPStatus, resp.StatusCode)
	}

	var parsed PredictResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("%w: decode json: %v", ErrInvalidResponse, err)
	}
	if len(parsed.Predictions) != len(flows) {
		return nil, fmt.Errorf("%w: expected %d predictions, got %d", ErrInvalidResponse, len(flows), len(parsed.Predictions))
	}

	requested := make(map[uuid.UUID]struct{}, len(flows))
	for _, f := range flows {
		requested[f.ID] = struct{}{}
	}

	out := make([]Prediction, 0, len(parsed.Predictions))
	seen := make(map[uuid.UUID]struct{}, len(parsed.Predictions))
	for i, p := range parsed.Predictions {
		id, err := uuid.Parse(strings.TrimSpace(p.FlowID))
		if err != nil {
			return nil, fmt.Errorf("%w: predictions[%d].flow_id: %v", ErrInvalidResponse, i, err)
		}
		if _, ok := requested[id]; !ok {
			return nil, fmt.Errorf("%w: unexpected flow_id %s", ErrInvalidResponse, id)
		}
		if _, dup := seen[id]; dup {
			return nil, fmt.Errorf("%w: duplicate flow_id %s", ErrInvalidResponse, id)
		}
		seen[id] = struct{}{}
		if err := ValidateProbabilities(p.Probabilities); err != nil {
			return nil, fmt.Errorf("%w: predictions[%d]", ErrInvalidProbabilities, i)
		}
		// Keep only required classes to avoid leaking unknown keys into the agent.
		probs := make(map[string]float64, len(RequiredClasses))
		for _, class := range RequiredClasses {
			probs[class] = p.Probabilities[class]
		}
		out = append(out, Prediction{FlowID: id, Probabilities: probs})
	}
	return out, nil
}

func flowToFeatures(f domain.Flow) FlowFeatures {
	return FlowFeatures{
		FlowID:       f.ID.String(),
		SrcIP:        f.SrcIP.String(),
		SrcMAC:       f.SrcMAC,
		DstIP:        f.DstIP.String(),
		DstMAC:       f.DstMAC,
		SrcPort:      f.SrcPort,
		DstPort:      f.DstPort,
		Protocol:     f.Protocol,
		DurationMs:   f.DurationMs,
		TotalPackets: f.TotalPackets,
		TotalBytes:   f.TotalBytes,
		TCPFlags: map[string]int64{
			"syn": f.TCPFlags.SYN,
			"ack": f.TCPFlags.ACK,
			"rst": f.TCPFlags.RST,
		},
	}
}
