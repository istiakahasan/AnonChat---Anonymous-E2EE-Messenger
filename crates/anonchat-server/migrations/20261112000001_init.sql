-- AnonChat Blind Relay PostgreSQL Schema Migration

CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(64) PRIMARY KEY,
    identity_key TEXT NOT NULL,
    identity_dh_key TEXT NOT NULL,
    signed_prekey_id INT NOT NULL,
    signed_prekey TEXT NOT NULL,
    signed_prekey_signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
    user_id VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    opk_id INT NOT NULL,
    opk_key TEXT NOT NULL,
    PRIMARY KEY (user_id, opk_id)
);

CREATE TABLE IF NOT EXISTS messages (
    id UUID PRIMARY KEY,
    recipient_id VARCHAR(64) NOT NULL,
    blob BYTEA NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);

