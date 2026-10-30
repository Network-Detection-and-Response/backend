package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// LimitRequestBody wraps the request body so reads beyond maxBytes fail.
// Callers should map *http.MaxBytesError to HTTP 413.
func LimitRequestBody(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil && maxBytes > 0 {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}
