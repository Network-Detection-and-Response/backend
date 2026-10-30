package ingestion

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

type stubProcessor struct {
	calls   atomic.Int64
	block   chan struct{}
	failErr error
}

func (s *stubProcessor) ProcessBatch(ctx context.Context, job BatchJob) error {
	s.calls.Add(1)
	if s.block != nil {
		<-s.block
	}
	return s.failErr
}

func TestQueueTryEnqueueAndProcess(t *testing.T) {
	proc := &stubProcessor{}
	q := NewQueue(4, 1, proc, slog.Default())
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
	q := NewQueue(1, 1, proc, slog.Default())

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

func TestQueueCountsPersistFailures(t *testing.T) {
	proc := &stubProcessor{failErr: errors.New("db down")}
	q := NewQueue(2, 1, proc, slog.Default())
	defer q.Shutdown(context.Background())

	if !q.TryEnqueue(BatchJob{BatchID: uuid.New()}) {
		t.Fatal("enqueue")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if q.PersistFailures() >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("expected persist failure counter")
}

func TestQueueShutdownDrainsAcceptedJobs(t *testing.T) {
	// Worker blocked on first job; second job sits in the buffer after 202-equivalent accept.
	release := make(chan struct{})
	proc := &stubProcessor{block: release}
	q := NewQueue(4, 1, proc, slog.Default())

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
