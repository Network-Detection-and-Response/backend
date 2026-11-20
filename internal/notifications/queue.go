package notifications

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
)

// Notifier is the non-blocking surface used by the ingestion pipeline.
type Notifier interface {
	Enqueue(inc domain.Incident)
}

// QueueConfig bounds the in-memory notification worker.
type QueueConfig struct {
	Capacity  int
	MaxTries  int
	BaseDelay time.Duration
}

func (c QueueConfig) normalized() QueueConfig {
	if c.Capacity < 1 {
		c.Capacity = 100
	}
	if c.MaxTries < 1 {
		c.MaxTries = 3
	}
	if c.BaseDelay <= 0 {
		c.BaseDelay = 500 * time.Millisecond
	}
	return c
}

// Queue is a bounded in-memory Telegram notification queue.
// It does not survive process restart; undelivered messages are lost.
type Queue struct {
	ch      chan domain.Incident
	sender  Sender
	cfg     QueueConfig
	log     *slog.Logger
	enabled bool
	wg      sync.WaitGroup
	cancel  context.CancelFunc
	ctx     context.Context
	dropped atomic.Int64
	failed  atomic.Int64
	sent    atomic.Int64
	mu      sync.Mutex
	closed  bool
}

// DisabledNotifier is used when Telegram is not configured.
type DisabledNotifier struct {
	log *slog.Logger
}

func NewDisabledNotifier(log *slog.Logger) *DisabledNotifier {
	if log == nil {
		log = slog.Default()
	}
	return &DisabledNotifier{log: log}
}

func (d *DisabledNotifier) Enqueue(inc domain.Incident) {
	d.log.Info("telegram_disabled_skip",
		"incident_id", inc.ID.String(),
		"severity", inc.Severity,
	)
}

// NewQueue starts a background worker when enabled and sender is non-nil.
// When disabled, returns a Queue that drops nothing but no-ops Enqueue with a log.
func NewQueue(enabled bool, sender Sender, cfg QueueConfig, log *slog.Logger) *Queue {
	if log == nil {
		log = slog.Default()
	}
	cfg = cfg.normalized()
	ctx, cancel := context.WithCancel(context.Background())
	q := &Queue{
		ch:      make(chan domain.Incident, cfg.Capacity),
		sender:  sender,
		cfg:     cfg,
		log:     log,
		enabled: enabled && sender != nil,
		ctx:     ctx,
		cancel:  cancel,
	}
	if !q.enabled {
		log.Info("telegram_notifications_disabled")
		return q
	}
	q.wg.Add(1)
	go q.worker()
	log.Info("telegram_notifications_enabled",
		"queue_capacity", cfg.Capacity,
		"max_attempts", cfg.MaxTries,
	)
	return q
}

// Enqueue never blocks the caller. Ineligible incidents are ignored.
// When the buffer is full the message is dropped and Dropped() increases.
func (q *Queue) Enqueue(inc domain.Incident) {
	if q == nil {
		return
	}
	if !domain.ShouldNotifyTelegram(inc.Severity, inc.Status) {
		return
	}
	if !q.enabled {
		q.log.Info("telegram_disabled_skip",
			"incident_id", inc.ID.String(),
			"severity", inc.Severity,
		)
		return
	}

	q.mu.Lock()
	closed := q.closed
	q.mu.Unlock()
	if closed {
		q.dropped.Add(1)
		q.log.Error("telegram_queue_closed_drop", "incident_id", inc.ID.String())
		return
	}

	select {
	case q.ch <- inc:
	default:
		q.dropped.Add(1)
		q.log.Error("telegram_queue_full",
			"incident_id", inc.ID.String(),
			"severity", inc.Severity,
		)
	}
}

func (q *Queue) Dropped() int64 { return q.dropped.Load() }
func (q *Queue) Failed() int64  { return q.failed.Load() }
func (q *Queue) Sent() int64    { return q.sent.Load() }

// Shutdown stops accepting work and waits for the worker (or ctx timeout).
func (q *Queue) Shutdown(ctx context.Context) {
	if q == nil {
		return
	}
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
		q.log.Info("telegram_queue_stopped",
			"sent", q.Sent(),
			"failed", q.Failed(),
			"dropped", q.Dropped(),
		)
	case <-ctx.Done():
		q.cancel()
		<-done
		q.log.Info("telegram_queue_stopped_after_cancel",
			"sent", q.Sent(),
			"failed", q.Failed(),
			"dropped", q.Dropped(),
		)
	}
}

func (q *Queue) worker() {
	defer q.wg.Done()
	for inc := range q.ch {
		q.deliver(inc)
	}
}

func (q *Queue) deliver(inc domain.Incident) {
	text := FormatIncidentMessage(inc)
	var lastErr error
	for attempt := 1; attempt <= q.cfg.MaxTries; attempt++ {
		if q.ctx.Err() != nil {
			q.failed.Add(1)
			q.log.Error("telegram_send_abandoned",
				"incident_id", inc.ID.String(),
				"attempt", attempt,
			)
			return
		}
		sendCtx, cancel := context.WithTimeout(q.ctx, 15*time.Second)
		lastErr = q.sender.Send(sendCtx, text)
		cancel()
		if lastErr == nil {
			q.sent.Add(1)
			q.log.Info("telegram_sent",
				"incident_id", inc.ID.String(),
				"severity", inc.Severity,
				"attempt", attempt,
			)
			return
		}
		q.log.Error("telegram_send_attempt_failed",
			"incident_id", inc.ID.String(),
			"attempt", attempt,
			"max_attempts", q.cfg.MaxTries,
			"error", lastErr.Error(),
		)
		if attempt == q.cfg.MaxTries {
			break
		}
		delay := q.cfg.BaseDelay * time.Duration(1<<(attempt-1))
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-q.ctx.Done():
			timer.Stop()
			q.failed.Add(1)
			return
		}
	}
	q.failed.Add(1)
	q.log.Error("telegram_send_exhausted",
		"incident_id", inc.ID.String(),
		"attempts", q.cfg.MaxTries,
	)
}
