package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	appauth "github.com/Network-Detection-and-Response/backend/internal/auth"
	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type memStore struct {
	users    map[string]domain.User // by normalized login
	byID     map[uuid.UUID]domain.User
	sessions map[string]domain.UserSession // by hex of token hash
}

func newMem() *memStore {
	return &memStore{
		users:    map[string]domain.User{},
		byID:     map[uuid.UUID]domain.User{},
		sessions: map[string]domain.UserSession{},
	}
}

func hashKey(b []byte) string { return string(b) }

func (m *memStore) CreateUser(ctx context.Context, user domain.User) (domain.User, error) {
	if _, ok := m.users[user.Login]; ok {
		return domain.User{}, postgres.ErrLoginTaken
	}
	m.users[user.Login] = user
	m.byID[user.ID] = user
	return user, nil
}

func (m *memStore) GetUserByNormalizedLogin(ctx context.Context, loginNormalized string) (domain.User, error) {
	u, ok := m.users[loginNormalized]
	if !ok {
		return domain.User{}, pgx.ErrNoRows
	}
	return u, nil
}

func (m *memStore) GetUserByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	u, ok := m.byID[id]
	if !ok {
		return domain.User{}, pgx.ErrNoRows
	}
	return u, nil
}

func (m *memStore) CreateSession(ctx context.Context, session domain.UserSession) (domain.UserSession, error) {
	m.sessions[hashKey(session.TokenHash)] = session
	return session, nil
}

func (m *memStore) GetActiveSessionByTokenHash(ctx context.Context, tokenHash []byte, now time.Time) (domain.UserSession, error) {
	s, ok := m.sessions[hashKey(tokenHash)]
	if !ok || !s.IsValid(now) {
		return domain.UserSession{}, pgx.ErrNoRows
	}
	return s, nil
}

func (m *memStore) RevokeSession(ctx context.Context, sessionID uuid.UUID, revokedAt time.Time) error {
	for k, s := range m.sessions {
		if s.ID == sessionID {
			s.RevokedAt = &revokedAt
			m.sessions[k] = s
			return nil
		}
	}
	return nil
}

func testService(store *memStore) *Service {
	svc := NewService(store, time.Hour)
	svc.Now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	svc.HashPassword = func(p string) (string, error) { return "hash:" + p, nil }
	svc.VerifyPassword = func(password, encodedHash string) error {
		if encodedHash == "hash:"+password {
			return nil
		}
		return appauth.ErrPasswordMismatch
	}
	n := 0
	svc.NewToken = func() (string, []byte, error) {
		n++
		raw := "token-" + string(rune('A'+n-1))
		return raw, appauth.HashSessionToken(raw), nil
	}
	return svc
}

func TestRegisterValidation(t *testing.T) {
	svc := testService(newMem())
	_, errs, err := svc.Register(context.Background(), "", "n", "ab", "short")
	if !errors.Is(err, ErrValidation) || len(errs) == 0 {
		t.Fatalf("want validation, got err=%v errs=%v", err, errs)
	}
}

func TestRegisterAndLoginAndLogout(t *testing.T) {
	store := newMem()
	svc := testService(store)
	ctx := context.Background()

	reg, _, err := svc.Register(ctx, "Name", "Nick", "UserOne", "password-15chars")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if reg.User.Login != "userone" {
		t.Fatalf("login normalized: %s", reg.User.Login)
	}
	if reg.RawToken == "" {
		t.Fatal("missing session token")
	}

	_, fieldErrs, err := svc.Register(ctx, "Name", "Nick", "USERONE", "password-15chars")
	if !errors.Is(err, ErrLoginConflict) || len(fieldErrs) == 0 {
		t.Fatalf("expected conflict, got err=%v fields=%v", err, fieldErrs)
	}

	login, _, err := svc.Login(ctx, "userone", "password-15chars")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	su, err := svc.ResolveSession(ctx, login.RawToken)
	if err != nil || su.User.ID != reg.User.ID {
		t.Fatalf("resolve: %v user=%v", err, su)
	}

	// Wrong password
	if _, _, err := svc.Login(ctx, "userone", "wrong-password-xx"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	// Unknown login
	if _, _, err := svc.Login(ctx, "nobody", "password-15chars"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown login: %v", err)
	}

	if err := svc.Logout(ctx, login.RawToken); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := svc.ResolveSession(ctx, login.RawToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked session still valid: %v", err)
	}
}

func TestExpiredAndForeignSession(t *testing.T) {
	store := newMem()
	svc := testService(store)
	ctx := context.Background()
	reg, _, err := svc.Register(ctx, "Name", "Nick", "alice", "password-15chars")
	if err != nil {
		t.Fatal(err)
	}

	// Expire by advancing clock past TTL
	svc.Now = func() time.Time { return time.Date(2026, 1, 3, 4, 5, 6, 0, time.UTC) }
	if _, err := svc.ResolveSession(ctx, reg.RawToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired: %v", err)
	}

	// Foreign / unknown token
	if _, err := svc.ResolveSession(ctx, "not-a-real-token"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("foreign: %v", err)
	}
}

func TestSessionIsValid(t *testing.T) {
	now := time.Now().UTC()
	rev := now.Add(-time.Minute)
	s := domain.UserSession{ExpiresAt: now.Add(time.Hour)}
	if !s.IsValid(now) {
		t.Fatal("expected valid")
	}
	s.RevokedAt = &rev
	if s.IsValid(now) {
		t.Fatal("revoked must be invalid")
	}
}
