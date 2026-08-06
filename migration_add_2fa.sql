-- ═══════════════════════════════════════════════════════════════════════════
-- MIGRATION — only needed if you already ran the OLD schema.sql against a
-- live database before this fix. The original schema.sql was missing the
-- two_factor_enabled column and the exe_login_codes table even though
-- main.py's login/2FA code already depended on both — this brings an
-- existing database in line with what the code actually expects.
--
-- Safe to run more than once (everything below is IF NOT EXISTS).
-- If you're setting up a brand new database instead, just run schema.sql
-- as normal — it already includes both of these.
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE exe_users
    ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS exe_login_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES exe_users(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_exe_login_codes_user ON exe_login_codes(user_id);
