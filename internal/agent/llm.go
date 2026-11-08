package agent

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
)

// HTTPLLMClient is an optional adapter. It POSTs a structured payload to
// LLM_BASE_URL and expects {"agent_verdict":"...","recommended_action":"..."}.
// It never accepts class/confidence/severity from the LLM response.
type HTTPLLMClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewHTTPLLMClient returns nil when apiKey is empty (LLM disabled).
func NewHTTPLLMClient(baseURL, apiKey string, timeout time.Duration) *HTTPLLMClient {
	if strings.TrimSpace(apiKey) == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPLLMClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

type llmRequest struct {
	AttackClass     string  `json:"attack_class"`
	Confidence      float64 `json:"confidence"`
	Severity        string  `json:"severity"`
	Status          string  `json:"status"`
	SrcIP           string  `json:"src_ip"`
	DstIP           string  `json:"dst_ip"`
	TemplateVerdict string  `json:"template_verdict"`
	TemplateAction  string  `json:"template_action"`
	Language        string  `json:"language"`
}

type llmResponse struct {
	AgentVerdict      string `json:"agent_verdict"`
	RecommendedAction string `json:"recommended_action"`
}

func (c *HTTPLLMClient) RewriteExplanation(v Verdict, flow domain.Flow, templateVerdict, templateAction string) (string, string, error) {
	if c == nil || c.baseURL == "" {
		return "", "", fmt.Errorf("llm not configured")
	}
	body, err := json.Marshal(llmRequest{
		AttackClass:     v.AttackClass,
		Confidence:      v.Confidence,
		Severity:        v.Severity,
		Status:          v.Status,
		SrcIP:           flow.SrcIP.String(),
		DstIP:           flow.DstIP.String(),
		TemplateVerdict: templateVerdict,
		TemplateAction:  templateAction,
		Language:        "ru",
	})
	if err != nil {
		return "", "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.httpClient.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/explain", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("llm status %d", resp.StatusCode)
	}
	var parsed llmResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", "", err
	}
	return strings.TrimSpace(parsed.AgentVerdict), strings.TrimSpace(parsed.RecommendedAction), nil
}
