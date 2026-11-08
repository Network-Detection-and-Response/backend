package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Network-Detection-and-Response/backend/internal/http/middleware"
	"github.com/gin-gonic/gin"
)

func TestSensorAPIKeyAcceptsValid(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.SensorAPIKey("secret-key"))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-Sensor-API-Key", "secret-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestSensorAPIKeyRejectsWrongAndDifferentLength(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.SensorAPIKey("secret-key"))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	cases := []string{"", "x", "wrong", "secret-key-extra", "short"}
	for _, key := range cases {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if key != "" {
			req.Header.Set("X-Sensor-API-Key", key)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("key=%q status=%d, want 401", key, w.Code)
		}
	}
}
