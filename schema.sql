-- ═══════════════════════════════════════════════════════════════════════════
-- EXE ACCOUNT SYSTEM — SCHEMA
-- Run this once against your Postgres database before starting the API.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS exe_users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'held', 'terminated')),
    two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Short-lived one-time login codes for email-based 2FA (main.py's
-- /auth/login + /auth/verify-2fa flow). This table was referenced by
-- main.py but missing from this file — added so a fresh `psql -f schema.sql`
-- actually matches what the API code expects.
CREATE TABLE IF NOT EXISTS exe_login_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES exe_users(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_exe_login_codes_user ON exe_login_codes(user_id);

-- Refresh tokens are stored hashed (never plaintext) so a DB leak alone
-- doesn't hand out working sessions. Each one is tied to one issued token
-- and gets revoked/rotated on every refresh (rotation = old one dies the
-- moment a new one is issued, so a stolen-then-reused refresh token gets
-- caught immediately).
CREATE TABLE IF NOT EXISTS exe_refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES exe_users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    app         TEXT,                 -- which app issued it, e.g. 'sentinel-desktop', 'sentinel-web'
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_exe_refresh_tokens_user ON exe_refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_exe_refresh_tokens_hash ON exe_refresh_tokens(token_hash);
