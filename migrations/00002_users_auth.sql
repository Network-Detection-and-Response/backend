-- +goose Up
-- +goose StatementBegin
CREATE TABLE users (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              TEXT NOT NULL,
    nickname          TEXT NOT NULL,
    login             TEXT NOT NULL,
    login_normalized  TEXT NOT NULL,
    password_hash     TEXT NOT NULL,
    is_active         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_name_len CHECK (char_length(name) BETWEEN 1 AND 80),
    CONSTRAINT users_nickname_len CHECK (char_length(nickname) BETWEEN 2 AND 32),
    CONSTRAINT users_login_len CHECK (char_length(login) BETWEEN 3 AND 32),
    CONSTRAINT users_login_normalized_len CHECK (char_length(login_normalized) BETWEEN 3 AND 32),
    CONSTRAINT users_password_hash_nonempty CHECK (char_length(password_hash) > 0)
);

CREATE UNIQUE INDEX users_login_normalized_uidx
    ON users (login_normalized);

CREATE INDEX users_is_active_idx
    ON users (is_active)
    WHERE is_active = TRUE;

CREATE TABLE user_sessions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   BYTEA NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ NULL,
    CONSTRAINT user_sessions_expires_after_created CHECK (expires_at > created_at),
    CONSTRAINT user_sessions_token_hash_len CHECK (octet_length(token_hash) = 32)
);

CREATE UNIQUE INDEX user_sessions_token_hash_uidx
    ON user_sessions (token_hash);

CREATE INDEX user_sessions_user_id_idx
    ON user_sessions (user_id);

CREATE INDEX user_sessions_active_lookup_idx
    ON user_sessions (token_hash)
    WHERE revoked_at IS NULL;

CREATE TABLE user_telegram_links (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    telegram_user_id  BIGINT NOT NULL,
    linked_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT user_telegram_links_user_id_uidx UNIQUE (user_id),
    CONSTRAINT user_telegram_links_telegram_user_id_uidx UNIQUE (telegram_user_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_telegram_links;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS users;
-- +goose StatementEnd
