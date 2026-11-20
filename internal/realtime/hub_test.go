package realtime_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/realtime"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

func TestEventEnvelopeFormat(t *testing.T) {
	inc := domain.Incident{
		ID:       uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Severity: domain.SeverityCritical,
		Status:   domain.StatusOpen,
	}
	evt, err := realtime.IncidentAlertEvent(inc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(evt)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"type", "timestamp", "data"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing envelope key %q in %s", key, raw)
		}
	}
	var typ string
	if err := json.Unmarshal(got["type"], &typ); err != nil || typ != realtime.TypeIncidentAlert {
		t.Fatalf("type=%v err=%v", typ, err)
	}
	var ts time.Time
	if err := json.Unmarshal(got["timestamp"], &ts); err != nil || ts.IsZero() {
		t.Fatalf("timestamp parse: %v %v", err, got["timestamp"])
	}
	var data realtime.IncidentAlertData
	if err := json.Unmarshal(got["data"], &data); err != nil {
		t.Fatal(err)
	}
	if data.IncidentID != inc.ID.String() || data.Severity != domain.SeverityCritical {
		t.Fatalf("data=%+v", data)
	}
}

func TestHubPublishAndDisconnect(t *testing.T) {
	hub := realtime.NewHub(realtime.Config{
		AllowedOrigins: []string{"http://localhost:5173"},
		ClientBuffer:   8,
		WriteWait:      2 * time.Second,
		PongWait:       3 * time.Second,
		PingPeriod:     time.Second,
	}, nil)
	defer hub.Shutdown()

	srv := httptest.NewServer(http.HandlerFunc(hub.ServeWS))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	evt, err := realtime.NewEvent(realtime.TypeFlowStats, realtime.FlowStatsData{
		BatchID:       uuid.New().String(),
		AcceptedFlows: 2,
		BytesTotal:    100,
		PacketsTotal:  10,
	})
	if err != nil {
		t.Fatal(err)
	}
	hub.Publish(evt)

	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var envelope realtime.Event
	if err := json.Unmarshal(msg, &envelope); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, msg)
	}
	if envelope.Type != realtime.TypeFlowStats {
		t.Fatalf("type=%s", envelope.Type)
	}
	if hub.ClientCount() != 1 {
		t.Fatalf("clients=%d", hub.ClientCount())
	}

	_ = conn.Close()
	deadlineWait := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadlineWait) {
		if hub.ClientCount() == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("client not removed after disconnect, count=%d", hub.ClientCount())
}

func TestHubRejectsDisallowedOrigin(t *testing.T) {
	hub := realtime.NewHub(realtime.Config{
		AllowedOrigins: []string{"http://localhost:5173"},
	}, nil)
	defer hub.Shutdown()

	srv := httptest.NewServer(http.HandlerFunc(hub.ServeWS))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	hdr := http.Header{}
	hdr.Set("Origin", "http://evil.example")
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err == nil {
		t.Fatal("expected origin rejection")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestHubAllowsConfiguredOrigin(t *testing.T) {
	hub := realtime.NewHub(realtime.Config{
		AllowedOrigins: []string{"http://localhost:5173"},
		ClientBuffer:   4,
		WriteWait:      2 * time.Second,
		PongWait:       3 * time.Second,
		PingPeriod:     time.Second,
	}, nil)
	defer hub.Shutdown()

	srv := httptest.NewServer(http.HandlerFunc(hub.ServeWS))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	hdr := http.Header{}
	hdr.Set("Origin", "http://localhost:5173")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err != nil {
		t.Fatalf("dial allowed origin: %v", err)
	}
	_ = conn.Close()
}

func TestHubConnectWithoutAuthHeaders(t *testing.T) {
	// Educational stand: dashboard WS matches REST — no user session/token required.
	hub := realtime.NewHub(realtime.Config{
		AllowedOrigins: []string{"http://localhost:5173"},
		ClientBuffer:   4,
		WriteWait:      2 * time.Second,
		PongWait:       3 * time.Second,
		PingPeriod:     time.Second,
	}, nil)
	defer hub.Shutdown()

	srv := httptest.NewServer(http.HandlerFunc(hub.ServeWS))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil) // no Authorization / API key
	if err != nil {
		t.Fatalf("unauthenticated dial should succeed on educational stand: %v", err)
	}
	defer conn.Close()

	evt, err := realtime.IncidentAlertEvent(domain.Incident{
		ID:       uuid.New(),
		Severity: domain.SeverityHigh,
		Status:   domain.StatusOpen,
	})
	if err != nil {
		t.Fatal(err)
	}
	hub.Publish(evt)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("unauthenticated client can receive events by design: %v", err)
	}
}

func TestHubMultipleClientsReceiveEvents(t *testing.T) {
	hub := realtime.NewHub(realtime.Config{
		ClientBuffer: 8,
		WriteWait:    2 * time.Second,
		PongWait:     3 * time.Second,
		PingPeriod:   time.Second,
	}, nil)
	defer hub.Shutdown()

	srv := httptest.NewServer(http.HandlerFunc(hub.ServeWS))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	const n = 3
	conns := make([]*websocket.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hub.ClientCount() == n {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if hub.ClientCount() != n {
		t.Fatalf("clients=%d want %d", hub.ClientCount(), n)
	}

	evt, err := realtime.NewEvent(realtime.TypeTopologyUpdated, realtime.TopologyUpdatedData{
		BatchID: uuid.New().String(), NodesUpserted: 2, EdgesUpserted: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	hub.Publish(evt)

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i, c := range conns {
		wg.Add(1)
		go func(i int, c *websocket.Conn) {
			defer wg.Done()
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, msg, err := c.ReadMessage()
			if err != nil {
				errs <- err
				return
			}
			var envelope realtime.Event
			if err := json.Unmarshal(msg, &envelope); err != nil {
				errs <- err
				return
			}
			if envelope.Type != realtime.TypeTopologyUpdated {
				errs <- errType(envelope.Type)
			}
		}(i, c)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

type errType string

func (e errType) Error() string { return "unexpected type: " + string(e) }

func TestHubShutdownClosesClients(t *testing.T) {
	hub := realtime.NewHub(realtime.Config{
		ClientBuffer: 4,
		WriteWait:    2 * time.Second,
		PongWait:     3 * time.Second,
		PingPeriod:   time.Second,
	}, nil)

	srv := httptest.NewServer(http.HandlerFunc(hub.ServeWS))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hub.ClientCount() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	done := make(chan struct{})
	go func() {
		hub.Shutdown()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Shutdown blocked")
	}
	if hub.ClientCount() != 0 {
		t.Fatalf("clients after shutdown=%d", hub.ClientCount())
	}

	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatal("expected read error after shutdown")
	}
}
