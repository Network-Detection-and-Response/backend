package domain

import (
	"time"

	"github.com/google/uuid"
)

// User is an application account (dashboard / Telegram notifications).
// Password material is never stored on this type beyond the Argon2id hash string.
type User struct {
	ID           uuid.UUID
	Name         string
	Nickname     string
	Login        string
	PasswordHash string
	IsActive     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserSession is a server-side session bound to a SHA-256 token hash.
type UserSession struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash []byte
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// IsValid reports whether the session is unrevoked and not expired at now.
func (s UserSession) IsValid(now time.Time) bool {
	if s.RevokedAt != nil {
		return false
	}
	return now.Before(s.ExpiresAt)
}
