package realtime

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPublishDoesNotBlockSlowClient(t *testing.T) {
	hub := NewHub(Config{ClientBuffer: 1}, nil)
	defer hub.Shutdown()

	// Register a client without writePump so the buffer never drains.
	c := &Client{
		hub:  hub,
		send: make(chan []byte, 1),
	}
	if !hub.register(c) {
		t.Fatal("register failed")
	}

	c.send <- []byte(`{"type":"seed"}`)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 32; i++ {
			evt, err := NewEvent(TypeTopologyUpdated, TopologyUpdatedData{
				BatchID:       uuid.New().String(),
				NodesUpserted: 1,
				EdgesUpserted: 1,
			})
			if err != nil {
				t.Errorf("event: %v", err)
				continue
			}
			hub.Publish(evt)
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on full client buffer")
	}
	if hub.Dropped() == 0 {
		t.Fatal("expected drops when client buffer is full")
	}

	// Avoid Shutdown double-closing send: unregister removes the fake client first.
	hub.unregister(c)
}
