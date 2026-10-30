package ingestion

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
)

// Processor persists an accepted batch. Defined as an interface for tests.
type Processor interface {
	ProcessBatch(ctx context.Context, job BatchJob) error
}

// Queue is a bounded in-memory work queue with a fixed worker pool.
// It does not survive process restarts; accepted-but-unprocessed jobs are lost.
type Queue struct {
	mu           sync.RWMutex
	ch           chan BatchJob
	closed       bool
	log          *slog.Logger
	processor    Processor
	wg           sync.WaitGroup
	persistFails atomic.Int64
}

// NewQueue creates a queue and starts workers. Call Shutdown on exit.
func NewQueue(capacity int, workerCount int, processor Processor, log *slog.Logger) *Queue {
	if capacity < 1 {
		capacity = 1
	}
	if workerCount < 1 {
		workerCount = 1
	}
	if log == nil {
		log = slog.Default()
	}
	q := &Queue{
		ch:        make(chan BatchJob, capacity),
		log:       log,
		processor: processor,
	}
	for i := 0; i < workerCount; i++ {
		q.wg.Add(1)
		go q.worker(i)
	}
	return q
}

// TryEnqueue places a job in the queue without blocking.
// Returns false when the queue is full or no longer accepting work.
// Callers must not treat the batch as accepted unless this returns true.
func (q *Queue) TryEnqueue(job BatchJob) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.closed {
		return false
	}
	select {
	case q.ch <- job:
		return true
	default:
		return false
	}
}

// PersistFailures returns how many batches failed during persistence (diagnostics).
func (q *Queue) PersistFailures() int64 {
	return q.persistFails.Load()
}

// Len returns the current number of queued (not yet taken by workers) jobs.
func (q *Queue) Len() int {
	return len(q.ch)
}

// Cap returns the queue buffer capacity.
func (q *Queue) Cap() int {
	return cap(q.ch)
}

// Shutdown stops accepting new jobs, closes the channel, and waits for workers
// to finish draining already-accepted jobs (including in-flight ProcessBatch).
// If ctx expires before drain completes, remaining accepted jobs may be lost —
// callers should allocate a dedicated shutdown budget after HTTP shutdown.
func (q *Queue) Shutdown(ctx context.Context) {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		close(q.ch)
	}
	q.mu.Unlock()

	done := make(chan struct{})
	go func() {
		q.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		q.log.Info("ingestion_queue_stopped")
	case <-ctx.Done():
		q.log.Error("ingestion_queue_shutdown_timeout",
			"error", "accepted batches may be lost; increase SHUTDOWN_TIMEOUT",
			"queued_remaining", len(q.ch),
		)
	}
}

func (q *Queue) worker(id int) {
	defer q.wg.Done()
	for job := range q.ch {
		ctx := context.Background()
		if err := q.processor.ProcessBatch(ctx, job); err != nil {
			q.persistFails.Add(1)
			q.log.Error("batch_persist_failed",
				"worker", id,
				"batch_id", job.BatchID.String(),
				"sensor_id", job.SensorID,
				"flows", len(job.Flows),
				"error", err.Error(),
			)
			continue
		}
		q.log.Info("batch_persisted",
			"worker", id,
			"batch_id", job.BatchID.String(),
			"sensor_id", job.SensorID,
			"flows", len(job.Flows),
		)
	}
}
