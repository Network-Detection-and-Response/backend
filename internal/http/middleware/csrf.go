package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/Network-Detection-and-Response/backend/internal/http/response"
	"github.com/gin-gonic/gin"
)

const CodeCSRF = "CSRF_REJECTED"

// ProtectStateChange validates Origin (preferred) or Referer against the allow-list
// for cookie-authenticated cross-origin SPAs. Safe methods pass through.
func ProtectStateChange(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		o = strings.TrimSpace(o)
		if o != "" {
			allowed[o] = struct{}{}
		}
	}

	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}

		origin := strings.TrimSpace(c.GetHeader("Origin"))
		if origin != "" {
			if _, ok := allowed[origin]; !ok {
				response.WriteError(c, http.StatusForbidden, CodeCSRF, "origin not allowed")
				return
			}
			c.Next()
			return
		}

		referer := strings.TrimSpace(c.GetHeader("Referer"))
		if referer == "" {
			response.WriteError(c, http.StatusForbidden, CodeCSRF, "missing origin")
			return
		}
		u, err := url.Parse(referer)
		if err != nil || u.Scheme == "" || u.Host == "" {
			response.WriteError(c, http.StatusForbidden, CodeCSRF, "invalid referer")
			return
		}
		refOrigin := u.Scheme + "://" + u.Host
		if _, ok := allowed[refOrigin]; !ok {
			response.WriteError(c, http.StatusForbidden, CodeCSRF, "referer not allowed")
			return
		}
		c.Next()
	}
}
