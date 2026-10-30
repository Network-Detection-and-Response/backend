package handlers

import (
	"errors"
	"io"
	"net/http"

	"github.com/Network-Detection-and-Response/backend/internal/http/response"
	"github.com/Network-Detection-and-Response/backend/internal/service/ingestion"
	"github.com/gin-gonic/gin"
)

// FlowEnqueuer accepts validated batches into the processing pipeline.
type FlowEnqueuer interface {
	TryEnqueue(job ingestion.BatchJob) bool
}

// Flows handles POST /api/v1/flows.
type Flows struct {
	Enqueuer         FlowEnqueuer
	MaxFlowsPerBatch int
}

// AcceptBatch validates the sensor payload and enqueues it for async persistence.
// Returns 202 only after a successful enqueue; 503 when the queue is full.
func (h *Flows) AcceptBatch(c *gin.Context) {
	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			response.WriteError(c, http.StatusRequestEntityTooLarge, response.CodePayloadTooLarge, "request body exceeds size limit")
			return
		}
		response.WriteError(c, http.StatusBadRequest, response.CodeValidation, "unable to read request body")
		return
	}

	job, err := ingestion.DecodeAndValidate(raw, h.MaxFlowsPerBatch)
	if err != nil {
		var ve *ingestion.ValidationError
		if errors.As(err, &ve) {
			status := http.StatusBadRequest
			code := response.CodeValidation
			if ve.Code == "PAYLOAD_TOO_LARGE" {
				status = http.StatusRequestEntityTooLarge
				code = response.CodePayloadTooLarge
			}
			response.WriteError(c, status, code, ve.Message)
			return
		}
		response.WriteError(c, http.StatusBadRequest, response.CodeValidation, err.Error())
		return
	}

	if h.Enqueuer == nil || !h.Enqueuer.TryEnqueue(job) {
		response.WriteError(c, http.StatusServiceUnavailable, response.CodeQueueFull,
			"processing queue is full; retry later")
		return
	}

	response.WriteData(c, http.StatusAccepted, gin.H{
		"batch_id":       job.BatchID.String(),
		"accepted_flows": len(job.Flows),
		"status":         "accepted",
	})
}
