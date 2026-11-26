package handlers

import (
	"errors"
	"net/http"
	"time"

	appauth "github.com/Network-Detection-and-Response/backend/internal/auth"
	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/http/middleware"
	"github.com/Network-Detection-and-Response/backend/internal/http/response"
	authsvc "github.com/Network-Detection-and-Response/backend/internal/service/auth"
	"github.com/gin-gonic/gin"
)

// Auth handles user registration and session endpoints.
type Auth struct {
	Service      *authsvc.Service
	CookieName   string
	CookieSecure bool
	SameSite     http.SameSite
}

type registerRequest struct {
	Name     string `json:"name"`
	Nickname string `json:"nickname"`
	Login    string `json:"login"`
	Password string `json:"password"`
}

type loginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type userDTO struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Nickname  string `json:"nickname"`
	Login     string `json:"login"`
	CreatedAt string `json:"created_at"`
}

func toUserDTO(u domain.User) userDTO {
	return userDTO{
		ID:        u.ID.String(),
		Name:      u.Name,
		Nickname:  u.Nickname,
		Login:     u.Login,
		CreatedAt: u.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// Register handles POST /api/v1/auth/register.
func (h *Auth) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.WriteError(c, http.StatusBadRequest, response.CodeValidation, "Некорректное тело запроса")
		return
	}

	result, fieldErrs, err := h.Service.Register(c.Request.Context(), req.Name, req.Nickname, req.Login, req.Password)
	if len(fieldErrs) > 0 {
		status := http.StatusBadRequest
		if errors.Is(err, authsvc.ErrLoginConflict) {
			status = http.StatusConflict
		}
		writeFieldErrors(c, status, fieldErrs)
		return
	}
	if err != nil {
		response.WriteError(c, http.StatusInternalServerError, response.CodeInternal, "Не удалось создать аккаунт")
		return
	}

	h.setSessionCookie(c, result.RawToken, result.Expires)
	response.WriteData(c, http.StatusCreated, toUserDTO(result.User))
}

// Login handles POST /api/v1/auth/login.
func (h *Auth) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.WriteError(c, http.StatusBadRequest, response.CodeValidation, "Некорректное тело запроса")
		return
	}

	result, fieldErrs, err := h.Service.Login(c.Request.Context(), req.Login, req.Password)
	if len(fieldErrs) > 0 {
		writeFieldErrors(c, http.StatusBadRequest, fieldErrs)
		return
	}
	if errors.Is(err, authsvc.ErrInvalidCredentials) {
		response.WriteError(c, http.StatusUnauthorized, response.CodeUnauthorized, "Неверный логин или пароль")
		return
	}
	if err != nil {
		response.WriteError(c, http.StatusInternalServerError, response.CodeInternal, "Не удалось выполнить вход")
		return
	}

	h.setSessionCookie(c, result.RawToken, result.Expires)
	response.WriteData(c, http.StatusOK, toUserDTO(result.User))
}

// Logout handles POST /api/v1/auth/logout.
func (h *Auth) Logout(c *gin.Context) {
	raw, _ := c.Cookie(h.CookieName)
	if raw != "" {
		_ = h.Service.Logout(c.Request.Context(), raw)
	}
	middleware.ClearAuthCookie(c, h.CookieName, h.CookieSecure, h.SameSite)
	response.WriteData(c, http.StatusOK, gin.H{"ok": true})
}

// Me handles GET /api/v1/auth/me.
func (h *Auth) Me(c *gin.Context) {
	raw, err := c.Cookie(h.CookieName)
	if err != nil || raw == "" {
		response.WriteUnauthorized(c, "Требуется авторизация")
		return
	}
	su, err := h.Service.ResolveSession(c.Request.Context(), raw)
	if err != nil {
		response.WriteUnauthorized(c, "Требуется авторизация")
		return
	}
	response.WriteData(c, http.StatusOK, toUserDTO(su.User))
}

func (h *Auth) setSessionCookie(c *gin.Context, rawToken string, expires time.Time) {
	maxAge := int(time.Until(expires).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}
	c.SetSameSite(h.SameSite)
	c.SetCookie(h.CookieName, rawToken, maxAge, "/", "", h.CookieSecure, true)
}

func writeFieldErrors(c *gin.Context, status int, errs []appauth.FieldError) {
	fields := make(map[string]string, len(errs))
	msg := "Ошибка валидации"
	if len(errs) > 0 {
		msg = errs[0].Message
		for _, e := range errs {
			fields[e.Field] = e.Message
		}
	}
	c.AbortWithStatusJSON(status, gin.H{
		"error": gin.H{
			"code":    response.CodeValidation,
			"message": msg,
			"fields":  fields,
		},
	})
}
