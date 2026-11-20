package httpapi_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/config"
	"github.com/Network-Detection-and-Response/backend/internal/domain"
	httpapi "github.com/Network-Detection-and-Response/backend/internal/http"
	"github.com/Network-Detection-and-Response/backend/internal/realtime"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

func TestWebSocketStreamEnvelopeAndDisconnect(t *testing.T) {
	hub := realtime.NewHub(realtime.Config{
		AllowedOrigins: []string{"http://localhost:5173"},
		ClientBuffer:   8,
		WriteWait:      2 * time.Second,
		PongWait:       3 * time.Second,
		PingPeriod:     time.Second,
	}, nil)
	defer hub.Shutdown()

	router := httpapi.NewRouter(httpapi.Dependencies{
		Config: config.Config{
			SensorAPIKey:       "test-sensor-key",
			MaxBodyBytes:       1 << 20,
			MaxFlowsPerBatch:   500,
			CORSAllowedOrigins: []string{"http://localhost:5173"},
		},
		FlowEnqueuer: &memQueue{},
		DB:           dbOK{},
		Realtime:     hub,
	})

	srv := httptest.NewServer(router)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/stream"
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v status=%v", err, resp)
	}

	inc := domain.Incident{
		ID:          uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		Severity:    domain.SeverityHigh,
		AttackClass: domain.AttackPortScan,
		Status:      domain.StatusOpen,
	}
	evt, err := realtime.IncidentAlertEvent(inc)
	if err != nil {
		t.Fatal(err)
	}
	hub.Publish(evt)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var envelope struct {
		Type      string          `json:"type"`
		Timestamp time.Time       `json:"timestamp"`
		Data      json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(msg, &envelope); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, msg)
	}
	if envelope.Type != realtime.TypeIncidentAlert {
		t.Fatalf("type=%s", envelope.Type)
	}
	if envelope.Timestamp.IsZero() || len(envelope.Data) == 0 {
		t.Fatalf("invalid envelope: %+v", envelope)
	}

	_ = conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hub.ClientCount() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("client still registered after disconnect: %d", hub.ClientCount())
}
