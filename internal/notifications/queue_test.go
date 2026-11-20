package notifications_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/notifications"
	"github.com/google/uuid"
)

type mockSender struct {
	calls   atomic.Int64
	failFor int64
	err     error
}

func (m *mockSender) Send(ctx context.Context, text string) error {
	n := m.calls.Add(1)
	if m.err != nil && n <= m.failFor {
		return m.err
	}
	if strings.Contains(text, "token") {
		return errors.New("message leaked token word unexpectedly")
	}
	return nil
}

func sampleHigh() domain.Incident {
	return domain.Incident{
		ID: uuid.New(), Severity: domain.SeverityHigh, Status: domain.StatusOpen,
		AttackClass: domain.AttackDDoS, MLConfidence: 0.9,
		SrcIP: netip.MustParseAddr("1.1.1.1"), DstIP: netip.MustParseAddr("2.2.2.2"),
		AgentVerdict: "v", RecommendedAction: "a",
	}
}

func TestQueueSendsHighSeverity(t *testing.T) {
	sender := &mockSender{}
	q := notifications.NewQueue(true, sender, notifications.QueueConfig{
		Capacity: 10, MaxTries: 2, BaseDelay: 5 * time.Millisecond,
	}, nil)
	defer q.Shutdown(context.Background())

	q.Enqueue(sampleHigh())
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if q.Sent() == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("sent=%d calls=%d", q.Sent(), sender.calls.Load())
}

func TestQueueSkipsMediumAndFalsePositive(t *testing.T) {
	sender := &mockSender{}
	q := notifications.NewQueue(true, sender, notifications.QueueConfig{Capacity: 10, MaxTries: 1, BaseDelay: time.Millisecond}, nil)
	defer q.Shutdown(context.Background())

	med := sampleHigh()
	med.Severity = domain.SeverityMedium
	q.Enqueue(med)
	fp := sampleHigh()
	fp.Status = domain.StatusFalsePositive
	q.Enqueue(fp)
	time.Sleep(50 * time.Millisecond)
	if sender.calls.Load() != 0 || q.Sent() != 0 {
		t.Fatalf("calls=%d sent=%d", sender.calls.Load(), q.Sent())
	}
}

func TestQueueRetriesThenSucceeds(t *testing.T) {
	sender := &mockSender{failFor: 2, err: errors.New("temp")}
	q := notifications.NewQueue(true, sender, notifications.QueueConfig{
		Capacity: 4, MaxTries: 3, BaseDelay: 5 * time.Millisecond,
	}, nil)
	defer q.Shutdown(context.Background())

	q.Enqueue(sampleHigh())
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if q.Sent() == 1 {
			if sender.calls.Load() < 3 {
				t.Fatalf("expected retries, calls=%d", sender.calls.Load())
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("not sent")
}

func TestQueueFullIsObservable(t *testing.T) {
	block := make(chan struct{})
	sender := &blockingSender{block: block}
	q := notifications.NewQueue(true, sender, notifications.QueueConfig{
		Capacity: 1, MaxTries: 1, BaseDelay: time.Millisecond,
	}, nil)
	defer func() {
		close(block)
		q.Shutdown(context.Background())
	}()

	q.Enqueue(sampleHigh()) // taken by worker or buffered
	q.Enqueue(sampleHigh()) // fill buffer / in-flight
	q.Enqueue(sampleHigh()) // likely drop
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if q.Dropped() >= 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("dropped=%d", q.Dropped())
}

type blockingSender struct{ block chan struct{} }

func (b *blockingSender) Send(ctx context.Context, text string) error {
	select {
	case <-b.block:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestDisabledQueueDoesNotCrash(t *testing.T) {
	q := notifications.NewQueue(false, nil, notifications.QueueConfig{}, nil)
	q.Enqueue(sampleHigh())
	q.Shutdown(context.Background())
}

func TestTelegramSenderMockHTTP(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	sender := notifications.NewTelegramSender(srv.URL, "TEST-TOKEN", "123", time.Second)
	if err := sender.Send(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotPath, "/botTEST-TOKEN/sendMessage") {
		t.Fatalf("path=%s", gotPath)
	}
}

func TestTelegramSenderErrorDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()
	sender := notifications.NewTelegramSender(srv.URL, "tok", "1", time.Second)
	q := notifications.NewQueue(true, sender, notifications.QueueConfig{
		Capacity: 2, MaxTries: 2, BaseDelay: 5 * time.Millisecond,
	}, nil)
	defer q.Shutdown(context.Background())
	q.Enqueue(sampleHigh())
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if q.Failed() == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("failed=%d", q.Failed())
}
