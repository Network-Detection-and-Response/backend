package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"strings"

	"github.com/Network-Detection-and-Response/backend/internal/http/response"
	"github.com/gin-gonic/gin"
)

const sensorAPIKeyHeader = "X-Sensor-API-Key"

// SensorAPIKey rejects requests without a valid sensor API key.
// Keys are compared via SHA-256 digests so ConstantTimeCompare always runs
// over equal-length inputs regardless of the provided key length.
func SensorAPIKey(expected string) gin.HandlerFunc {
	expectedDigest := sha256.Sum256([]byte(expected))
	return func(c *gin.Context) {
		provided := strings.TrimSpace(c.GetHeader(sensorAPIKeyHeader))
		if provided == "" {
			response.WriteUnauthorized(c, "missing X-Sensor-API-Key header")
			return
		}
		providedDigest := sha256.Sum256([]byte(provided))
		if subtle.ConstantTimeCompare(providedDigest[:], expectedDigest[:]) != 1 {
			response.WriteUnauthorized(c, "invalid sensor API key")
			return
		}
		c.Next()
	}
}
