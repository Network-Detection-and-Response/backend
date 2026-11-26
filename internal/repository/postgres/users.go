package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrLoginTaken is returned when login_normalized already exists.
var ErrLoginTaken = errors.New("login already taken")

// CreateUser inserts a new user row.
func (s *Store) CreateUser(ctx context.Context, user domain.User) (domain.User, error) {
	const q = `
INSERT INTO users (id, name, nickname, login, login_normalized, password_hash, is_active, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, name, nickname, login, password_hash, is_active, created_at, updated_at`
	row := s.pool.QueryRow(ctx, q,
		user.ID,
		user.Name,
		user.Nickname,
		user.Login,
		user.Login, // already normalized by service
		user.PasswordHash,
		user.IsActive,
		user.CreatedAt,
		user.UpdatedAt,
	)
	var out domain.User
	err := row.Scan(
		&out.ID, &out.Name, &out.Nickname, &out.Login, &out.PasswordHash,
		&out.IsActive, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return domain.User{}, ErrLoginTaken
		}
		return domain.User{}, err
	}
	return out, nil
}

// GetUserByNormalizedLogin loads a user by case-insensitive login.
func (s *Store) GetUserByNormalizedLogin(ctx context.Context, loginNormalized string) (domain.User, error) {
	const q = `
SELECT id, name, nickname, login, password_hash, is_active, created_at, updated_at
FROM users
WHERE login_normalized = $1`
	var out domain.User
	err := s.pool.QueryRow(ctx, q, loginNormalized).Scan(
		&out.ID, &out.Name, &out.Nickname, &out.Login, &out.PasswordHash,
		&out.IsActive, &out.CreatedAt, &out.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, pgx.ErrNoRows
	}
	return out, err
}

// GetUserByID loads a user by id.
func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	const q = `
SELECT id, name, nickname, login, password_hash, is_active, created_at, updated_at
FROM users
WHERE id = $1`
	var out domain.User
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&out.ID, &out.Name, &out.Nickname, &out.Login, &out.PasswordHash,
		&out.IsActive, &out.CreatedAt, &out.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, pgx.ErrNoRows
	}
	return out, err
}

// CreateSession stores a hashed session token.
func (s *Store) CreateSession(ctx context.Context, session domain.UserSession) (domain.UserSession, error) {
	const q = `
INSERT INTO user_sessions (id, user_id, token_hash, created_at, expires_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, user_id, token_hash, created_at, expires_at, revoked_at`
	var out domain.UserSession
	err := s.pool.QueryRow(ctx, q,
		session.ID, session.UserID, session.TokenHash, session.CreatedAt, session.ExpiresAt, session.RevokedAt,
	).Scan(&out.ID, &out.UserID, &out.TokenHash, &out.CreatedAt, &out.ExpiresAt, &out.RevokedAt)
	return out, err
}

// GetActiveSessionByTokenHash returns an unrevoked, unexpired session for the token hash.
func (s *Store) GetActiveSessionByTokenHash(ctx context.Context, tokenHash []byte, now time.Time) (domain.UserSession, error) {
	const q = `
SELECT id, user_id, token_hash, created_at, expires_at, revoked_at
FROM user_sessions
WHERE token_hash = $1
  AND revoked_at IS NULL
  AND expires_at > $2`
	var out domain.UserSession
	err := s.pool.QueryRow(ctx, q, tokenHash, now).Scan(
		&out.ID, &out.UserID, &out.TokenHash, &out.CreatedAt, &out.ExpiresAt, &out.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.UserSession{}, pgx.ErrNoRows
	}
	return out, err
}

// RevokeSession marks a session as revoked.
func (s *Store) RevokeSession(ctx context.Context, sessionID uuid.UUID, revokedAt time.Time) error {
	const q = `
UPDATE user_sessions
SET revoked_at = $2
WHERE id = $1 AND revoked_at IS NULL`
	_, err := s.pool.Exec(ctx, q, sessionID, revokedAt)
	return err
}

// UserHasPlainPasswordColumn is a defensive check used by tests: ensure no plaintext column exists.
func (s *Store) UserPasswordColumnNames(ctx context.Context) ([]string, error) {
	const q = `
SELECT column_name
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'users'
ORDER BY ordinal_position`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}
