package notifications

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

// Sender delivers a notification message. Implementations must not log secrets.
type Sender interface {
	Send(ctx context.Context, text string) error
}

// TelegramSender posts to the Bot API sendMessage endpoint.
type TelegramSender struct {
	apiBase string
	token   string
	chatID  string
	client  *http.Client
}

// NewTelegramSender builds a Bot API client. apiBase defaults to https://api.telegram.org.
// token must never be logged by callers.
func NewTelegramSender(apiBase, token, chatID string, timeout time.Duration) *TelegramSender {
	if strings.TrimSpace(apiBase) == "" {
		apiBase = "https://api.telegram.org"
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &TelegramSender{
		apiBase: strings.TrimRight(apiBase, "/"),
		token:   token,
		chatID:  chatID,
		client:  &http.Client{Timeout: timeout},
	}
}

func (t *TelegramSender) Send(ctx context.Context, text string) error {
	url := fmt.Sprintf("%s/bot%s/sendMessage", t.apiBase, t.token)
	body, err := json.Marshal(map[string]any{
		"chat_id": t.chatID,
		"text":    text,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram status %d", resp.StatusCode)
	}
	return nil
}

// FormatIncidentMessage builds a Russian advisory alert without secrets.
func FormatIncidentMessage(inc domain.Incident) string {
	return fmt.Sprintf(
		"NDR alert\nseverity: %s\nclass: %s\nconfidence: %.2f\nsrc: %s\ndst: %s\nid: %s\n%s\n%s",
		inc.Severity,
		inc.AttackClass,
		inc.MLConfidence,
		inc.SrcIP.String(),
		inc.DstIP.String(),
		inc.ID.String(),
		inc.AgentVerdict,
		inc.RecommendedAction,
	)
}
