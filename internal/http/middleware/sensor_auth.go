package middleware

import (
	"crypto/subtle"
	"strings"

	"github.com/Network-Detection-and-Response/backend/internal/http/response"
	"github.com/gin-gonic/gin"
)

const sensorAPIKeyHeader = "X-Sensor-API-Key"

// SensorAPIKey rejects requests without a valid sensor API key.
// Comparison uses constant-time equality when key lengths match.
func SensorAPIKey(expected string) gin.HandlerFunc {
	return func(c *gin.Context) {
		provided := strings.TrimSpace(c.GetHeader(sensorAPIKeyHeader))
		if provided == "" {
			response.WriteUnauthorized(c, "missing X-Sensor-API-Key header")
			return
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
			response.WriteUnauthorized(c, "invalid sensor API key")
			return
		}
		c.Next()
	}
}
