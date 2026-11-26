package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/http/response"
	"github.com/gin-gonic/gin"
)

const CodeRateLimited = "RATE_LIMITED"

// RateLimiter is a lightweight per-key sliding window limiter (in-process).
type RateLimiter struct {
	mu      sync.Mutex
	window  time.Duration
	limit   int
	entries map[string]*rlBucket
	now     func() time.Time
}

type rlBucket struct {
	times []time.Time
}

// NewRateLimiter creates a limiter that allows `limit` events per `window` per key.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	if limit <= 0 {
		limit = 10
	}
	if window <= 0 {
		window = 15 * time.Minute
	}
	return &RateLimiter{
		window:  window,
		limit:   limit,
		entries: make(map[string]*rlBucket),
		now:     time.Now,
	}
}

// Allow reports whether the key may proceed and records the attempt when allowed.
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	cutoff := now.Add(-r.window)
	b := r.entries[key]
	if b == nil {
		b = &rlBucket{}
		r.entries[key] = b
	}
	kept := b.times[:0]
	for _, t := range b.times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	b.times = kept
	if len(b.times) >= r.limit {
		return false
	}
	b.times = append(b.times, now)
	// Opportunistic cleanup of idle keys.
	if len(r.entries) > 10_000 {
		for k, v := range r.entries {
			if len(v.times) == 0 {
				delete(r.entries, k)
			}
		}
	}
	return true
}

// LimitByIP rejects with 429 when the client IP exceeds the limiter.
func LimitByIP(limiter *RateLimiter, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := action + ":" + c.ClientIP()
		if !limiter.Allow(key) {
			response.WriteError(c, http.StatusTooManyRequests, CodeRateLimited, "Слишком много запросов. Попробуйте позже.")
			return
		}
		c.Next()
	}
}
