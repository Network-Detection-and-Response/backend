package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// DBPinger is the minimal DB dependency for readiness checks.
type DBPinger interface {
	Ping(ctx context.Context) error
}

// Health handles liveness and readiness probes.
type Health struct {
	DB DBPinger
}

// Healthz returns 200 when the process is alive.
func (h *Health) Healthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Readyz returns 200 when PostgreSQL is reachable, otherwise 503.
func (h *Health) Readyz(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "not_ready",
			"error": gin.H{
				"code":    "DB_UNAVAILABLE",
				"message": "database connection is not configured",
			},
		})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	if err := h.DB.Ping(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status": "not_ready",
			"error": gin.H{
				"code":    "DB_UNAVAILABLE",
				"message": "database is unreachable",
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ready"})
}
