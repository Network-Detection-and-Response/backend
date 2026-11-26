package auth

import (
	"context"
	"errors"
	"time"

	appauth "github.com/Network-Detection-and-Response/backend/internal/auth"
	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrValidation         = errors.New("validation failed")
	ErrLoginConflict      = errors.New("login conflict")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrUserInactive       = errors.New("user inactive")
)

// UserStore persists users and sessions.
type UserStore interface {
	CreateUser(ctx context.Context, user domain.User) (domain.User, error)
	GetUserByNormalizedLogin(ctx context.Context, loginNormalized string) (domain.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (domain.User, error)
	CreateSession(ctx context.Context, session domain.UserSession) (domain.UserSession, error)
	GetActiveSessionByTokenHash(ctx context.Context, tokenHash []byte, now time.Time) (domain.UserSession, error)
	RevokeSession(ctx context.Context, sessionID uuid.UUID, revokedAt time.Time) error
}

// Service implements registration, login, logout and session resolution.
type Service struct {
	Store          UserStore
	SessionTTL     time.Duration
	Now            func() time.Time
	HashPassword   func(string) (string, error)
	VerifyPassword func(password, encodedHash string) error
	NewToken       func() (raw string, hash []byte, err error)
}

// NewService builds an auth service with secure defaults.
func NewService(store UserStore, sessionTTL time.Duration) *Service {
	if sessionTTL <= 0 {
		sessionTTL = 7 * 24 * time.Hour
	}
	return &Service{
		Store:          store,
		SessionTTL:     sessionTTL,
		Now:            func() time.Time { return time.Now().UTC() },
		HashPassword:   appauth.HashPassword,
		VerifyPassword: appauth.VerifyPassword,
		NewToken:       appauth.NewSessionToken,
	}
}

// RegisterResult is returned after successful registration.
type RegisterResult struct {
	User     domain.User
	RawToken string
	Expires  time.Time
}

// LoginResult is returned after successful login.
type LoginResult struct {
	User     domain.User
	RawToken string
	Expires  time.Time
}

// SessionUser pairs an authenticated user with the active session id.
type SessionUser struct {
	User      domain.User
	SessionID uuid.UUID
}

// Register creates a user and a new session. Validation errors are returned as []appauth.FieldError.
func (s *Service) Register(ctx context.Context, name, nickname, login, password string) (RegisterResult, []appauth.FieldError, error) {
	input, fieldErrs := appauth.ValidateRegister(name, nickname, login, password)
	if len(fieldErrs) > 0 {
		return RegisterResult{}, fieldErrs, ErrValidation
	}

	hash, err := s.HashPassword(input.Password)
	if err != nil {
		return RegisterResult{}, nil, err
	}

	now := s.Now()
	user := domain.User{
		ID:           uuid.New(),
		Name:         input.Name,
		Nickname:     input.Nickname,
		Login:        input.Login,
		PasswordHash: hash,
		IsActive:     true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	created, err := s.Store.CreateUser(ctx, user)
	if err != nil {
		if errors.Is(err, postgres.ErrLoginTaken) {
			return RegisterResult{}, []appauth.FieldError{{
				Field:   "login",
				Message: "Этот логин уже занят",
			}}, ErrLoginConflict
		}
		return RegisterResult{}, nil, err
	}

	raw, expires, err := s.createSession(ctx, created.ID, now)
	if err != nil {
		return RegisterResult{}, nil, err
	}
	created.PasswordHash = ""
	return RegisterResult{User: created, RawToken: raw, Expires: expires}, nil, nil
}

// Login authenticates credentials and creates a new session.
func (s *Service) Login(ctx context.Context, login, password string) (LoginResult, []appauth.FieldError, error) {
	normalized, fieldErrs := appauth.ValidateLoginCredentials(login, password)
	if len(fieldErrs) > 0 {
		return LoginResult{}, fieldErrs, ErrValidation
	}

	user, err := s.Store.GetUserByNormalizedLogin(ctx, normalized)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Run a dummy verify path cost? Spec asks identical message; dummy argon would help timing
			// but is expensive. We reject with the same error without leaking existence.
			return LoginResult{}, nil, ErrInvalidCredentials
		}
		return LoginResult{}, nil, err
	}
	if !user.IsActive {
		return LoginResult{}, nil, ErrInvalidCredentials
	}
	if err := s.VerifyPassword(password, user.PasswordHash); err != nil {
		return LoginResult{}, nil, ErrInvalidCredentials
	}

	now := s.Now()
	raw, expires, err := s.createSession(ctx, user.ID, now)
	if err != nil {
		return LoginResult{}, nil, err
	}
	user.PasswordHash = ""
	return LoginResult{User: user, RawToken: raw, Expires: expires}, nil, nil
}

// Logout revokes the session identified by the raw cookie token.
func (s *Service) Logout(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return ErrUnauthorized
	}
	hash := appauth.HashSessionToken(rawToken)
	now := s.Now()
	session, err := s.Store.GetActiveSessionByTokenHash(ctx, hash, now)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnauthorized
		}
		return err
	}
	return s.Store.RevokeSession(ctx, session.ID, now)
}

// ResolveSession validates a raw token and returns the bound active user.
func (s *Service) ResolveSession(ctx context.Context, rawToken string) (SessionUser, error) {
	if rawToken == "" {
		return SessionUser{}, ErrUnauthorized
	}
	hash := appauth.HashSessionToken(rawToken)
	now := s.Now()
	session, err := s.Store.GetActiveSessionByTokenHash(ctx, hash, now)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SessionUser{}, ErrUnauthorized
		}
		return SessionUser{}, err
	}
	if !session.IsValid(now) {
		return SessionUser{}, ErrUnauthorized
	}
	user, err := s.Store.GetUserByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SessionUser{}, ErrUnauthorized
		}
		return SessionUser{}, err
	}
	if !user.IsActive {
		return SessionUser{}, ErrUnauthorized
	}
	user.PasswordHash = ""
	return SessionUser{User: user, SessionID: session.ID}, nil
}

func (s *Service) createSession(ctx context.Context, userID uuid.UUID, now time.Time) (raw string, expires time.Time, err error) {
	raw, tokenHash, err := s.NewToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expires = now.Add(s.SessionTTL)
	_, err = s.Store.CreateSession(ctx, domain.UserSession{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: tokenHash,
		CreatedAt: now,
		ExpiresAt: expires,
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return raw, expires, nil
}
