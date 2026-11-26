package middleware

import (
	"net/http"

	"github.com/Network-Detection-and-Response/backend/internal/http/response"
	authsvc "github.com/Network-Detection-and-Response/backend/internal/service/auth"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	ContextUserIDKey    = "auth_user_id"
	ContextSessionIDKey = "auth_session_id"
	ContextUserKey      = "auth_user"
)

// SessionResolver loads the current user from a session cookie value.
type SessionResolver interface {
	ResolveSession(c *gin.Context, rawToken string) (authsvc.SessionUser, error)
}

// RequireSession rejects unauthenticated requests after resolving the cookie.
func RequireSession(cookieName string, resolve func(c *gin.Context, rawToken string) (authsvc.SessionUser, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, err := c.Cookie(cookieName)
		if err != nil || raw == "" {
			response.WriteUnauthorized(c, "Требуется авторизация")
			return
		}
		su, err := resolve(c, raw)
		if err != nil {
			response.WriteUnauthorized(c, "Требуется авторизация")
			return
		}
		c.Set(ContextUserIDKey, su.User.ID)
		c.Set(ContextSessionIDKey, su.SessionID)
		c.Set(ContextUserKey, su.User)
		c.Next()
	}
}

// UserIDFromContext returns the authenticated user id when present.
func UserIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get(ContextUserIDKey)
	if !ok {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok
}

// ClearAuthCookie writes an expired cookie with the same Path/SameSite/Secure flags.
func ClearAuthCookie(c *gin.Context, name string, secure bool, sameSite http.SameSite) {
	c.SetSameSite(sameSite)
	c.SetCookie(name, "", -1, "/", "", secure, true)
}
