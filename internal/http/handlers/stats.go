package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/http/response"
	"github.com/Network-Detection-and-Response/backend/internal/service/stats"
	"github.com/gin-gonic/gin"
)

// Stats handles GET /api/v1/stats/* endpoints.
type Stats struct {
	Service *stats.Service
}

// Overview returns aggregated telemetry and incident counts for a period.
// Additive fields (tcp_flags, sensors) preserve backward compatibility for existing clients.
func (h *Stats) Overview(c *gin.Context) {
	period := c.DefaultQuery("period", "24h")
	ov, err := h.Service.Overview(c.Request.Context(), period)
	if err != nil {
		if errors.Is(err, stats.ErrValidation) {
			response.WriteError(c, http.StatusBadRequest, response.CodeValidation, err.Error())
			return
		}
		response.WriteError(c, http.StatusInternalServerError, response.CodeInternal, "failed to load stats")
		return
	}
	response.WriteData(c, http.StatusOK, gin.H{
		"period":                ov.Period,
		"flows_total":           ov.FlowsTotal,
		"bytes_total":           ov.BytesTotal,
		"packets_total":         ov.PacketsTotal,
		"incidents_total":       ov.IncidentsTotal,
		"incidents_by_severity": ov.IncidentsBySeverity,
		"protocols":             ov.Protocols,
		"tcp_flags":             ov.TCPFlags,
		"sensors":               ov.Sensors,
	})
}

// Timeseries returns the last hour of flow traffic grouped by UTC minute.
// Query: period=1h (only supported value; default 1h). Empty minutes are zero-filled.
func (h *Stats) Timeseries(c *gin.Context) {
	period := c.DefaultQuery("period", "1h")
	if period != "" && period != "1h" {
		response.WriteError(c, http.StatusBadRequest, response.CodeValidation,
			"period must be 1h (minute buckets for the last hour)")
		return
	}
	ts, err := h.Service.TimeseriesLastHour(c.Request.Context())
	if err != nil {
		response.WriteError(c, http.StatusInternalServerError, response.CodeInternal, "failed to load timeseries")
		return
	}
	response.WriteData(c, http.StatusOK, gin.H{
		"period":   ts.Period,
		"bucket":   ts.Bucket,
		"timezone": ts.Timezone,
		"from":     ts.From.UTC().Format(time.RFC3339),
		"to":       ts.To.UTC().Format(time.RFC3339),
		"points":   ts.Points,
	})
}
