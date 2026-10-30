package ingestion

import (
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/google/uuid"
)

// BatchJob is an accepted flow batch waiting for (or undergoing) persistence.
//
// Idempotency: each successful HTTP accept generates a new BatchID. Replaying the
// same request body after a 202 creates a second batch and duplicate flow rows.
// Safe client policy: do not retry after 202; retry only after 503 or a transport
// failure before a response (ambiguous timeouts still risk duplicates).
type BatchJob struct {
	BatchID    uuid.UUID
	SensorID   string
	ObservedAt time.Time
	Flows      []domain.Flow
}
