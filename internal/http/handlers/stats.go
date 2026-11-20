package handlers

import (
	"errors"
	"net/http"

	"github.com/Network-Detection-and-Response/backend/internal/http/response"
	"github.com/Network-Detection-and-Response/backend/internal/service/stats"
	"github.com/gin-gonic/gin"
)

// Stats handles GET /api/v1/stats/overview.
type Stats struct {
	Service *stats.Service
}

// Overview returns aggregated telemetry and incident counts for a period.
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
	})
}
