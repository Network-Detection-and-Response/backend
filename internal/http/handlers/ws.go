package handlers

import (
	"github.com/Network-Detection-and-Response/backend/internal/realtime"
	"github.com/gin-gonic/gin"
)

// Stream handles GET /ws/stream WebSocket upgrades for the dashboard.
type Stream struct {
	Hub *realtime.Hub
}

// Serve upgrades the connection when the hub is configured.
func (h *Stream) Serve(c *gin.Context) {
	if h == nil || h.Hub == nil {
		c.Status(503)
		return
	}
	h.Hub.ServeWS(c.Writer, c.Request)
}
