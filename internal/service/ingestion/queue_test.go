package ingestion

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func fastRetry(maxAttempts int) RetryPolicy {
	return RetryPolicy{MaxAttempts: maxAttempts, BaseDelay: time.Millisecond}
}

type stubProcessor struct {
	calls   atomic.Int64
	block   chan struct{}
	failErr error
	failN   atomic.Int64 // fail first N calls, then succeed (0 = use failErr always if set)
	mu      sync.Mutex
	started chan struct{}
	once    sync.Once
}

func (s *stubProcessor) ProcessBatch(ctx context.Context, job BatchJob) error {
	s.calls.Add(1)
	s.once.Do(func() {
		if s.started != nil {
			close(s.started)
		}
	})
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if n := s.failN.Load(); n > 0 {
		if s.calls.Load() <= n {
			return errors.New("transient db error")
		}
		return nil
	}
	return s.failErr
}

func TestQueueTryEnqueueAndProcess(t *testing.T) {
	proc := &stubProcessor{}
	q := NewQueue(4, 1, fastRetry(3), proc, slog.Default())
	defer q.Shutdown(context.Background())

	ok := q.TryEnqueue(BatchJob{BatchID: uuid.New(), SensorID: "s"})
	if !ok {
		t.Fatal("enqueue should succeed")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if proc.calls.Load() >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("processor was not called")
}

func TestQueueFullReturnsFalse(t *testing.T) {
	block := make(chan struct{})
	proc := &stubProcessor{block: block}
	q := NewQueue(1, 1, fastRetry(1), proc, slog.Default())

	// Fill worker + buffer: first job taken by worker (blocked), second fills buffer.
	if !q.TryEnqueue(BatchJob{BatchID: uuid.New()}) {
		t.Fatal("first enqueue")
	}
	// Wait until worker picks up the first job.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && proc.calls.Load() < 1 {
		time.Sleep(5 * time.Millisecond)
	}
	if !q.TryEnqueue(BatchJob{BatchID: uuid.New()}) {
		t.Fatal("second enqueue should fill buffer")
	}
	if q.TryEnqueue(BatchJob{BatchID: uuid.New()}) {
		t.Fatal("third enqueue should fail when full")
	}

	close(block)
	q.Shutdown(context.Background())
}

func TestQueueCountsPersistFailuresAfterRetries(t *testing.T) {
	proc := &stubProcessor{failErr: errors.New("db down")}
	q := NewQueue(2, 1, fastRetry(3), proc, slog.Default())
	defer q.Shutdown(context.Background())

	if !q.TryEnqueue(BatchJob{BatchID: uuid.New()}) {
		t.Fatal("enqueue")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if q.PersistFailures() >= 1 {
			if proc.calls.Load() != 3 {
				t.Fatalf("calls=%d, want 3 attempts before permanent failure", proc.calls.Load())
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected persist failure counter after exhausted retries")
}

func TestQueueRetriesThenSucceeds(t *testing.T) {
	proc := &stubProcessor{}
	proc.failN.Store(2) // fail first two attempts, succeed on third
	q := NewQueue(2, 1, fastRetry(3), proc, slog.Default())
	defer q.Shutdown(context.Background())

	if !q.TryEnqueue(BatchJob{BatchID: uuid.New(), SensorID: "retry-ok"}) {
		t.Fatal("enqueue")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if proc.calls.Load() >= 3 && q.PersistFailures() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("calls=%d persist_fails=%d", proc.calls.Load(), q.PersistFailures())
}

func TestQueueFailingJobDoesNotBlockOtherWorkers(t *testing.T) {
	var (
		slowStarted = make(chan struct{})
		releaseSlow = make(chan struct{})
		fastDone    = make(chan struct{})
	)

	slow := &blockingThenFailProcessor{started: slowStarted, release: releaseSlow}
	fast := &signalOnSuccessProcessor{done: fastDone}
	mux := &routingProcessor{slow: slow, fast: fast}

	q := NewQueue(4, 2, fastRetry(3), mux, slog.Default())
	defer q.Shutdown(context.Background())

	if !q.TryEnqueue(BatchJob{BatchID: uuid.New(), SensorID: "slow"}) {
		t.Fatal("enqueue slow")
	}
	select {
	case <-slowStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("slow job did not start")
	}
	if !q.TryEnqueue(BatchJob{BatchID: uuid.New(), SensorID: "fast"}) {
		t.Fatal("enqueue fast")
	}
	select {
	case <-fastDone:
	case <-time.After(2 * time.Second):
		t.Fatal("fast job blocked behind slow failing job")
	}
	close(releaseSlow)
}

type blockingThenFailProcessor struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *blockingThenFailProcessor) ProcessBatch(ctx context.Context, job BatchJob) error {
	p.once.Do(func() { close(p.started) })
	select {
	case <-p.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return errors.New("slow fail")
}

type signalOnSuccessProcessor struct {
	done chan struct{}
	once sync.Once
}

func (p *signalOnSuccessProcessor) ProcessBatch(ctx context.Context, job BatchJob) error {
	p.once.Do(func() { close(p.done) })
	return nil
}

type routingProcessor struct {
	slow Processor
	fast Processor
}

func (r *routingProcessor) ProcessBatch(ctx context.Context, job BatchJob) error {
	if job.SensorID == "slow" {
		return r.slow.ProcessBatch(ctx, job)
	}
	return r.fast.ProcessBatch(ctx, job)
}

func TestQueueShutdownDrainsAcceptedJobs(t *testing.T) {
	// Worker blocked on first job; second job sits in the buffer after 202-equivalent accept.
	release := make(chan struct{})
	proc := &stubProcessor{block: release}
	q := NewQueue(4, 1, fastRetry(1), proc, slog.Default())

	if !q.TryEnqueue(BatchJob{BatchID: uuid.New(), SensorID: "a"}) {
		t.Fatal("enqueue 1")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && proc.calls.Load() < 1 {
		time.Sleep(5 * time.Millisecond)
	}
	if !q.TryEnqueue(BatchJob{BatchID: uuid.New(), SensorID: "b"}) {
		t.Fatal("enqueue 2")
	}

	done := make(chan struct{})
	go func() {
		q.Shutdown(context.Background())
		close(done)
	}()

	// Shutdown must not finish until both accepted jobs are processed.
	select {
	case <-done:
		t.Fatal("Shutdown returned before drain completed")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not finish after workers unblocked")
	}
	if proc.calls.Load() < 2 {
		t.Fatalf("processed=%d, want >= 2 drained accepted jobs", proc.calls.Load())
	}
}

func TestQueueShutdownTimeoutCancelsAndWaitsForWorkers(t *testing.T) {
	started := make(chan struct{})
	proc := &stubProcessor{block: make(chan struct{}), started: started}
	q := NewQueue(4, 1, fastRetry(1), proc, slog.Default())

	if !q.TryEnqueue(BatchJob{BatchID: uuid.New(), SensorID: "slow"}) {
		t.Fatal("enqueue")
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not start ProcessBatch")
	}

	// Second job remains buffered; timeout should abandon it after cancel.
	if !q.TryEnqueue(BatchJob{BatchID: uuid.New(), SensorID: "queued"}) {
		t.Fatal("enqueue buffered")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		q.Shutdown(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return after canceling workers")
	}

	if q.AbandonedBatches() < 1 {
		t.Fatalf("abandoned=%d, want >= 1 after shutdown cancel", q.AbandonedBatches())
	}
	// Workers must be fully stopped: further enqueue rejected and Len==0.
	if q.TryEnqueue(BatchJob{BatchID: uuid.New()}) {
		t.Fatal("queue must reject enqueue after Shutdown")
	}
}

func TestQueueShutdownTimeoutAbandonsDuringBackoff(t *testing.T) {
	proc := &stubProcessor{failErr: errors.New("db down")}
	// Long backoff so shutdown timeout hits while waiting to retry.
	q := NewQueue(2, 1, RetryPolicy{MaxAttempts: 5, BaseDelay: 500 * time.Millisecond}, proc, slog.Default())

	if !q.TryEnqueue(BatchJob{BatchID: uuid.New(), SensorID: "backoff"}) {
		t.Fatal("enqueue")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && proc.calls.Load() < 1 {
		time.Sleep(5 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	q.Shutdown(ctx)

	if q.AbandonedBatches() < 1 && q.PersistFailures() < 1 {
		t.Fatal("expected abandon or exhausted failure after shutdown during backoff")
	}
	if q.PersistFailures() > 0 && proc.calls.Load() >= 5 {
		t.Fatal("should not complete all retries when shutdown canceled mid-backoff")
	}
}
