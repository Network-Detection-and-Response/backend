package ingestion

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Processor persists an accepted batch. Defined as an interface for tests.
type Processor interface {
	ProcessBatch(ctx context.Context, job BatchJob) error
}

// RetryPolicy bounds persistence retries for a single accepted batch.
// Retries run inside the worker that owns the job so one failing batch
// cannot stall other workers. The in-memory queue does not survive process
// crashes; retries do not provide durable delivery guarantees.
type RetryPolicy struct {
	MaxAttempts int           // inclusive; must be >= 1 (default 3)
	BaseDelay   time.Duration // exponential base: BaseDelay * 2^(attempt-1) (default 100ms)
}

// DefaultRetryPolicy returns the production defaults.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{MaxAttempts: 3, BaseDelay: 100 * time.Millisecond}
}

func (r RetryPolicy) normalized() RetryPolicy {
	if r.MaxAttempts < 1 {
		r.MaxAttempts = 3
	}
	if r.BaseDelay <= 0 {
		r.BaseDelay = 100 * time.Millisecond
	}
	return r
}

// Queue is a bounded in-memory work queue with a fixed worker pool.
// It does not survive process restarts; accepted-but-unprocessed jobs are lost.
type Queue struct {
	mu            sync.RWMutex
	ch            chan BatchJob
	closed        bool
	log           *slog.Logger
	processor     Processor
	retry         RetryPolicy
	wg            sync.WaitGroup
	processCtx    context.Context
	processCancel context.CancelFunc
	persistFails  atomic.Int64
	abandoned     atomic.Int64
}

// NewQueue creates a queue and starts workers. Call Shutdown on exit.
// Shutdown always waits until every worker has stopped before returning, so
// callers may close shared resources (e.g. the DB pool) safely afterwards.
func NewQueue(capacity int, workerCount int, retry RetryPolicy, processor Processor, log *slog.Logger) *Queue {
	if capacity < 1 {
		capacity = 1
	}
	if workerCount < 1 {
		workerCount = 1
	}
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	q := &Queue{
		ch:            make(chan BatchJob, capacity),
		log:           log,
		processor:     processor,
		retry:         retry.normalized(),
		processCtx:    ctx,
		processCancel: cancel,
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

// PersistFailures returns how many batches exhausted all persistence attempts.
func (q *Queue) PersistFailures() int64 {
	return q.persistFails.Load()
}

// AbandonedBatches returns how many accepted batches were dropped because
// shutdown canceled in-flight work or drained the channel after a timeout.
func (q *Queue) AbandonedBatches() int64 {
	return q.abandoned.Load()
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
// to finish. Already-accepted jobs are processed until ctx expires; then
// in-flight ProcessBatch contexts are canceled, remaining buffered jobs are
// abandoned while draining, and Shutdown blocks until every worker exits.
// Callers must not release shared resources (DB pool) until Shutdown returns.
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
		return
	case <-ctx.Done():
		q.log.Error("ingestion_queue_shutdown_timeout",
			"error", "canceling in-flight persistence; remaining accepted batches will be abandoned",
			"queued_remaining", len(q.ch),
		)
		q.processCancel()
		<-done
		q.log.Info("ingestion_queue_stopped_after_cancel",
			"persist_failures", q.PersistFailures(),
			"abandoned_batches", q.AbandonedBatches(),
		)
	}
}

func (q *Queue) worker(id int) {
	defer q.wg.Done()
	for job := range q.ch {
		if q.processCtx.Err() != nil {
			q.abandoned.Add(1)
			q.log.Error("batch_abandoned_on_shutdown",
				"worker", id,
				"batch_id", job.BatchID.String(),
				"sensor_id", job.SensorID,
				"flows", len(job.Flows),
			)
			continue
		}
		q.processWithRetry(id, job)
	}
}

func (q *Queue) processWithRetry(id int, job BatchJob) {
	var lastErr error
	for attempt := 1; attempt <= q.retry.MaxAttempts; attempt++ {
		if q.processCtx.Err() != nil {
			q.abandoned.Add(1)
			q.log.Error("batch_abandoned_on_shutdown",
				"worker", id,
				"batch_id", job.BatchID.String(),
				"sensor_id", job.SensorID,
				"attempt", attempt,
				"flows", len(job.Flows),
			)
			return
		}

		lastErr = q.processor.ProcessBatch(q.processCtx, job)
		if lastErr == nil {
			q.log.Info("batch_persisted",
				"worker", id,
				"batch_id", job.BatchID.String(),
				"sensor_id", job.SensorID,
				"attempt", attempt,
				"flows", len(job.Flows),
			)
			return
		}

		// Shutdown cancel is not a permanent persist failure.
		if errors.Is(lastErr, context.Canceled) || errors.Is(lastErr, context.DeadlineExceeded) || q.processCtx.Err() != nil {
			q.abandoned.Add(1)
			q.log.Error("batch_abandoned_on_shutdown",
				"worker", id,
				"batch_id", job.BatchID.String(),
				"sensor_id", job.SensorID,
				"attempt", attempt,
				"flows", len(job.Flows),
				"error", lastErr.Error(),
			)
			return
		}

		q.log.Error("batch_persist_attempt_failed",
			"worker", id,
			"batch_id", job.BatchID.String(),
			"sensor_id", job.SensorID,
			"attempt", attempt,
			"max_attempts", q.retry.MaxAttempts,
			"flows", len(job.Flows),
			"error", lastErr.Error(),
		)

		if attempt == q.retry.MaxAttempts {
			break
		}

		delay := q.retry.BaseDelay * time.Duration(1<<(attempt-1))
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-q.processCtx.Done():
			timer.Stop()
			q.abandoned.Add(1)
			q.log.Error("batch_abandoned_on_shutdown",
				"worker", id,
				"batch_id", job.BatchID.String(),
				"sensor_id", job.SensorID,
				"attempt", attempt,
				"flows", len(job.Flows),
			)
			return
		}
	}

	q.persistFails.Add(1)
	errMsg := "unknown"
	if lastErr != nil {
		errMsg = lastErr.Error()
	}
	q.log.Error("batch_persist_exhausted",
		"worker", id,
		"batch_id", job.BatchID.String(),
		"sensor_id", job.SensorID,
		"attempts", q.retry.MaxAttempts,
		"flows", len(job.Flows),
		"error", errMsg,
	)
}
