package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/http/response"
	"github.com/Network-Detection-and-Response/backend/internal/service/incidents"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Incidents handles dashboard incident endpoints.
type Incidents struct {
	Service *incidents.Service
}

type incidentDTO struct {
	IncidentID        string  `json:"incident_id"`
	CreatedAt         string  `json:"created_at"`
	FlowID            *string `json:"flow_id"`
	SrcIP             string  `json:"src_ip"`
	SrcMAC            *string `json:"src_mac"`
	DstIP             string  `json:"dst_ip"`
	DstMAC            *string `json:"dst_mac"`
	AttackClass       string  `json:"attack_class"`
	Severity          string  `json:"severity"`
	Status            string  `json:"status"`
	MLConfidence      float64 `json:"ml_confidence"`
	AgentVerdict      string  `json:"agent_verdict"`
	RecommendedAction string  `json:"recommended_action"`
}

func toIncidentDTO(inc domain.Incident) incidentDTO {
	dto := incidentDTO{
		IncidentID:        inc.ID.String(),
		CreatedAt:         inc.CreatedAt.UTC().Format(time.RFC3339),
		SrcIP:             inc.SrcIP.String(),
		SrcMAC:            inc.SrcMAC,
		DstIP:             inc.DstIP.String(),
		DstMAC:            inc.DstMAC,
		AttackClass:       inc.AttackClass,
		Severity:          inc.Severity,
		Status:            inc.Status,
		MLConfidence:      inc.MLConfidence,
		AgentVerdict:      inc.AgentVerdict,
		RecommendedAction: inc.RecommendedAction,
	}
	if inc.FlowID != nil {
		s := inc.FlowID.String()
		dto.FlowID = &s
	}
	return dto
}

// List handles GET /api/v1/incidents.
func (h *Incidents) List(c *gin.Context) {
	page, err := parsePositiveInt(c.DefaultQuery("page", "1"), "page")
	if err != nil {
		response.WriteError(c, http.StatusBadRequest, response.CodeValidation, err.Error())
		return
	}
	pageSize, err := parsePositiveInt(c.DefaultQuery("page_size", "20"), "page_size")
	if err != nil {
		response.WriteError(c, http.StatusBadRequest, response.CodeValidation, err.Error())
		return
	}

	result, err := h.Service.List(c.Request.Context(), incidents.ListQuery{
		Page:     page,
		PageSize: pageSize,
		Severity: c.Query("severity"),
		Status:   c.Query("status"),
		Since:    c.Query("since"),
		Until:    c.Query("until"),
	})
	if err != nil {
		if errors.Is(err, incidents.ErrValidation) {
			response.WriteError(c, http.StatusBadRequest, response.CodeValidation, err.Error())
			return
		}
		response.WriteError(c, http.StatusInternalServerError, response.CodeInternal, "failed to list incidents")
		return
	}

	items := make([]incidentDTO, 0, len(result.Items))
	for _, inc := range result.Items {
		items = append(items, toIncidentDTO(inc))
	}
	response.WriteData(c, http.StatusOK, gin.H{
		"items":     items,
		"page":      result.Page,
		"page_size": result.PageSize,
		"total":     result.Total,
	})
}

// Get handles GET /api/v1/incidents/{id}.
func (h *Incidents) Get(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.WriteError(c, http.StatusBadRequest, response.CodeValidation, "incident id must be a UUID")
		return
	}
	inc, err := h.Service.Get(c.Request.Context(), id)
	if err != nil {
		if errors.Is(err, incidents.ErrNotFound) {
			response.WriteError(c, http.StatusNotFound, response.CodeNotFound, "incident not found")
			return
		}
		response.WriteError(c, http.StatusInternalServerError, response.CodeInternal, "failed to load incident")
		return
	}
	response.WriteData(c, http.StatusOK, toIncidentDTO(inc))
}

type patchIncidentRequest struct {
	Status string `json:"status"`
}

// Patch handles PATCH /api/v1/incidents/{id}.
func (h *Incidents) Patch(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		response.WriteError(c, http.StatusBadRequest, response.CodeValidation, "incident id must be a UUID")
		return
	}
	var req patchIncidentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.WriteError(c, http.StatusBadRequest, response.CodeValidation, "invalid JSON body")
		return
	}
	if req.Status == "" {
		response.WriteError(c, http.StatusBadRequest, response.CodeValidation, "status is required")
		return
	}

	inc, err := h.Service.PatchStatus(c.Request.Context(), id, req.Status)
	if err != nil {
		switch {
		case errors.Is(err, incidents.ErrNotFound):
			response.WriteError(c, http.StatusNotFound, response.CodeNotFound, "incident not found")
		case errors.Is(err, incidents.ErrValidation):
			response.WriteError(c, http.StatusBadRequest, response.CodeValidation, err.Error())
		case errors.Is(err, incidents.ErrConflict):
			response.WriteError(c, http.StatusConflict, response.CodeConflict, err.Error())
		default:
			response.WriteError(c, http.StatusInternalServerError, response.CodeInternal, "failed to update incident")
		}
		return
	}
	response.WriteData(c, http.StatusOK, toIncidentDTO(inc))
}

func parsePositiveInt(raw, name string) (int, error) {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, errors.New(name + " must be a positive integer")
	}
	return n, nil
}
