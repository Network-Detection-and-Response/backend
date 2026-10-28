package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type stubDB struct {
	err error
}

func (s stubDB) Ping(ctx context.Context) error {
	return s.err
}

func TestHealthz(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Health{}
	r := gin.New()
	r.GET("/healthz", h.Healthz)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestReadyzDBUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Health{DB: stubDB{err: errors.New("down")}}
	r := gin.New()
	r.GET("/readyz", h.Readyz)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestReadyzOK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Health{DB: stubDB{}}
	r := gin.New()
	r.GET("/readyz", h.Readyz)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}
