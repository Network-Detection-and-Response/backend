package realtime

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Config tunes hub and per-connection behaviour.
type Config struct {
	AllowedOrigins []string
	ClientBuffer   int
	WriteWait      time.Duration
	PongWait       time.Duration
	PingPeriod     time.Duration
}

func (c Config) normalized() Config {
	if c.ClientBuffer < 1 {
		c.ClientBuffer = 64
	}
	if c.WriteWait <= 0 {
		c.WriteWait = 10 * time.Second
	}
	if c.PongWait <= 0 {
		c.PongWait = 60 * time.Second
	}
	if c.PingPeriod <= 0 {
		// Keepalive must be shorter than pong wait.
		c.PingPeriod = (c.PongWait * 9) / 10
	}
	if c.PingPeriod >= c.PongWait {
		c.PingPeriod = c.PongWait / 2
	}
	return c
}

// Hub fans out events to connected dashboard clients without blocking publishers.
//
// Auth note: Origin checks only restrict browser Origins (same list as CORS).
// They are not user authentication. Like other dashboard REST endpoints on the
// educational stand, /ws/stream does not require a session/token.
type Hub struct {
	cfg      Config
	log      *slog.Logger
	upgrader websocket.Upgrader

	mu      sync.RWMutex
	clients map[*Client]struct{}
	closed  atomic.Bool
	dropped atomic.Int64
	wg      sync.WaitGroup
}

// NewHub constructs a hub. Callers should Publish from processing paths and
// ServeWS from GET /ws/stream. Shutdown closes all clients and waits for pumps.
func NewHub(cfg Config, log *slog.Logger) *Hub {
	cfg = cfg.normalized()
	if log == nil {
		log = slog.Default()
	}
	h := &Hub{
		cfg:     cfg,
		log:     log,
		clients: make(map[*Client]struct{}),
	}
	allowed := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		allowed[o] = struct{}{}
	}
	h.upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				// Non-browser clients (curl, native apps) typically omit Origin.
				return true
			}
			_, ok := allowed[origin]
			return ok
		},
	}
	return h
}

// Publish marshals and fans out an event. Never blocks on a slow client;
// full buffers drop that client's copy of the event.
func (h *Hub) Publish(evt Event) {
	if h == nil || h.closed.Load() {
		return
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		h.log.Error("ws_event_marshal_failed", "type", evt.Type, "error", err.Error())
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		select {
		case c.send <- payload:
		default:
			h.dropped.Add(1)
		}
	}
}

// Dropped returns how many per-client event deliveries were skipped due to a full buffer.
func (h *Hub) Dropped() int64 { return h.dropped.Load() }

// ClientCount returns the number of connected clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// register adds a client. Returns false if the hub is already shut down.
func (h *Hub) register(c *Client) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed.Load() {
		return false
	}
	h.clients[c] = struct{}{}
	return true
}

func (h *Hub) unregister(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c]; !ok {
		return
	}
	delete(h.clients, c)
	close(c.send)
}

// Shutdown marks the hub closed, disconnects all clients and waits for read/write pumps.
func (h *Hub) Shutdown() {
	if h == nil {
		return
	}
	if !h.closed.CompareAndSwap(false, true) {
		return
	}
	h.mu.Lock()
	for c := range h.clients {
		delete(h.clients, c)
		close(c.send)
		if c.conn != nil {
			_ = c.conn.Close()
		}
	}
	h.mu.Unlock()
	h.wg.Wait()
}

// ServeWS upgrades the HTTP connection and runs read/write pumps until disconnect.
func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.closed.Load() {
		http.Error(w, "websocket unavailable", http.StatusServiceUnavailable)
		return
	}
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Info("ws_upgrade_failed", "error", err.Error(), "remote", r.RemoteAddr)
		return
	}
	client := &Client{
		hub:  h,
		conn: conn,
		send: make(chan []byte, h.cfg.ClientBuffer),
	}
	if !h.register(client) {
		_ = conn.Close()
		return
	}

	h.wg.Add(2)
	go func() {
		defer h.wg.Done()
		client.writePump()
	}()
	defer h.wg.Done()
	client.readPump()
}
