package handlers

import (
	"net/http"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/http/response"
	"github.com/Network-Detection-and-Response/backend/internal/service/topology"
	"github.com/gin-gonic/gin"
)

// Topology handles GET /api/v1/topology.
type Topology struct {
	Service *topology.Service
}

// Get returns the observed communication graph (not a verified physical topology).
func (h *Topology) Get(c *gin.Context) {
	graph, err := h.Service.Get(c.Request.Context())
	if err != nil {
		response.WriteError(c, http.StatusInternalServerError, response.CodeInternal, "failed to load topology")
		return
	}

	nodes := make([]gin.H, 0, len(graph.Nodes))
	for _, n := range graph.Nodes {
		nodes = append(nodes, gin.H{
			"id":             n.ID,
			"label":          n.Label,
			"ip":             n.IP,
			"mac":            n.MAC,
			"device_type":    n.DeviceType,
			"is_compromised": n.IsCompromised,
			"last_seen":      n.LastSeen.Format(time.RFC3339),
		})
	}
	edges := make([]gin.H, 0, len(graph.Edges))
	for _, e := range graph.Edges {
		edges = append(edges, gin.H{
			"id":              e.ID,
			"source":          e.Source,
			"target":          e.Target,
			"protocol":        e.Protocol,
			"total_bytes":     e.TotalBytes,
			"is_under_attack": e.IsUnderAttack,
			"last_seen":       e.LastSeen.Format(time.RFC3339),
		})
	}
	response.WriteData(c, http.StatusOK, gin.H{
		"nodes": nodes,
		"edges": edges,
	})
}
