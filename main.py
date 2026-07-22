# EXE ACCOUNT API — Centralized Auth for EXE Development
# Start command: uvicorn main:app --host 0.0.0.0 --port $PORT
from __future__ import annotations
import os, secrets, hashlib, json, urllib.request, urllib.error
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
import psycopg2
import psycopg2.extras
from psycopg2 import pool as pg_pool
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
DATABASE_URL          = os.environ["DATABASE_URL"]
JWT_SECRET            = os.environ["JWT_SECRET"]              # generate with secrets.token_urlsafe(48)
JWT_ALGO              = "HS256"
ACCESS_TOKEN_MINUTES  = 15
REFRESH_TOKEN_DAYS    = 30

# First account registered with this email is auto-promoted to admin.
# Set this to your own email before you register your first account.
ADMIN_BOOTSTRAP_EMAIL = os.environ.get("ADMIN_BOOTSTRAP_EMAIL", "").lower().strip()

# Resend (transactional email over HTTPS). Render's free web services block
# outbound SMTP ports (25/465/587), so plain smtplib mail doesn't work there —
# Resend's API runs over normal HTTPS instead. Get a key at resend.com/api-keys.
# MAIL_FROM must be an address on a domain you've verified with Resend, or use
# their shared "onboarding@resend.dev" sender for testing.
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
MAIL_FROM = os.environ.get("MAIL_FROM", "EXE Accounts <onboarding@resend.dev>")
PUBLIC_APP_URL = os.environ.get("PUBLIC_APP_URL", "")  # used to build verify/reset links

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="EXE Account API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten to your real domains + tauri://localhost once stable
    allow_methods=["*"],
    allow_headers=["*"],
)

db_pool = pg_pool.SimpleConnectionPool(1, 10, dsn=DATABASE_URL)

def get_conn():
    conn = db_pool.getconn()
    try:
        yield conn
    finally:
        db_pool.putconn(conn)

# ─────────────────────────────────────────────────────────────────────────────
# MODELS
# ─────────────────────────────────────────────────────────────────────────────
class RegisterBody(BaseModel):
    email: EmailStr
    password: str
    display_name: str
    app: Optional[str] = None   # e.g. "sentinel-desktop", "sentinel-web"

class LoginBody(BaseModel):
    email: EmailStr
    password: str
    app: Optional[str] = None

class RefreshBody(BaseModel):
    refresh_token: str

class LogoutBody(BaseModel):
    refresh_token: str

class ForgotPasswordBody(BaseModel):
    email: EmailStr

class ResetPasswordBody(BaseModel):
    token: str
    new_password: str

# ─────────────────────────────────────────────────────────────────────────────
# TOKEN HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _hash_refresh_token(raw: str) -> str:
    # Refresh tokens are opaque random strings — we only ever store the hash,
    # same principle as password storage, so a DB leak alone isn't a session leak.
    return hashlib.sha256(raw.encode()).hexdigest()

def make_access_token(user_id: str, email: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "email": email,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def make_refresh_token(conn, user_id: str, app_name: Optional[str]) -> str:
    raw = secrets.token_urlsafe(48)
    token_hash = _hash_refresh_token(raw)
    expires_at = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_DAYS)
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO exe_refresh_tokens (user_id, token_hash, app, expires_at) "
            "VALUES (%s, %s, %s, %s)",
            (user_id, token_hash, app_name, expires_at),
        )
    conn.commit()
    return raw

def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Access token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid access token")

def require_user(authorization: str = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    return decode_access_token(token)

def require_admin(user=Depends(require_user), conn=Depends(get_conn)) -> dict:
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT is_admin FROM exe_users WHERE id = %s", (user["sub"],))
        row = cur.fetchone()
    if not row or not row["is_admin"]:
        raise HTTPException(403, "Admin access required")
    return user

# ─────────────────────────────────────────────────────────────────────────────
# EMAIL — verification + password reset
# ─────────────────────────────────────────────────────────────────────────────
def make_action_token(user_id: str, kind: str, minutes: int) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": user_id, "kind": kind, "iat": now, "exp": now + timedelta(minutes=minutes)},
        JWT_SECRET, algorithm=JWT_ALGO,
    )

def decode_action_token(token: str, expected_kind: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(400, "This link has expired — request a new one")
    except jwt.InvalidTokenError:
        raise HTTPException(400, "This link is invalid")
    if payload.get("kind") != expected_kind:
        raise HTTPException(400, "This link is invalid")
    return payload["sub"]

def send_email(to: str, subject: str, html: str) -> None:
    if not RESEND_API_KEY:
        print(f"[mailer] RESEND_API_KEY not configured — skipping email to {to}: {subject}")
        return
    payload = json.dumps({"from": MAIL_FROM, "to": [to], "subject": subject, "html": html}).encode()
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        method="POST",
        headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            resp.read()
    except Exception as e:
        # Best-effort — a failed email shouldn't take down register/login.
        print(f"[mailer] failed to send to {to}: {e}")

EMAIL_TEMPLATE = """<div style="background:#0a0a0a;padding:40px 20px;font-family:sans-serif;">
  <div style="max-width:420px;margin:0 auto;background:#111;border:1px solid rgba(255,255,255,0.12);border-radius:10px;padding:32px;text-align:center;">
    <h1 style="color:#e8e8e8;font-size:18px;letter-spacing:1px;margin:0 0 12px;">{title}</h1>
    <p style="color:rgba(232,232,232,0.6);font-size:14px;line-height:1.5;margin:0 0 24px;">{message}</p>
    <a href="{link}" style="display:inline-block;background:rgba(255,255,255,0.1);border:1px solid rgba(255,255,255,0.25);color:#fff;padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:700;letter-spacing:1px;font-size:13px;">{button_label}</a>
    <p style="color:rgba(232,232,232,0.3);font-size:11px;margin:24px 0 0;">If the button doesn't work, paste this link into your browser:<br>{link}</p>
  </div>
</div>"""

def send_verification_email(user_id: str, email: str) -> None:
    token = make_action_token(user_id, "verify_email", minutes=60 * 24)
    link = f"{PUBLIC_APP_URL}/auth/verify-email?token={token}" if PUBLIC_APP_URL else f"(set PUBLIC_APP_URL) /auth/verify-email?token={token}"
    html = EMAIL_TEMPLATE.format(
        title="Verify your EXE account",
        message="Click below to verify this email address. This link expires in 24 hours.",
        link=link, button_label="VERIFY EMAIL",
    )
    send_email(email, "Verify your EXE account", html)

VERIFY_PAGE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>EXE Account</title>
<style>
  body {{ background:#0a0a0a; color:#e8e8e8; font-family:sans-serif; display:flex;
          align-items:center; justify-content:center; height:100vh; margin:0; }}
  .box {{ text-align:center; max-width:380px; padding:32px; }}
  h1 {{ font-size:20px; letter-spacing:1px; margin-bottom:10px; color:{color}; }}
  p {{ font-size:14px; color:rgba(232,232,232,0.6); }}
</style></head>
<body><div class="box"><h1>{title}</h1><p>{message}</p></div></body></html>"""

def send_password_reset_email(user_id: str, email: str) -> None:
    token = make_action_token(user_id, "pwd_reset", minutes=60)
    link = f"{PUBLIC_APP_URL}/reset-password?token={token}" if PUBLIC_APP_URL else f"(set PUBLIC_APP_URL) /reset-password?token={token}"
    html = EMAIL_TEMPLATE.format(
        title="Reset your EXE account password",
        message="Click below to reset your password. This link expires in 1 hour. If you didn't request this, ignore this email.",
        link=link, button_label="RESET PASSWORD",
    )
    send_email(email, "Reset your EXE account password", html)

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES — AUTH
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/auth/register")
def register(body: RegisterBody, conn=Depends(get_conn)):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id FROM exe_users WHERE email = %s", (body.email,))
        if cur.fetchone():
            raise HTTPException(409, "An account with this email already exists")

        password_hash = pwd_ctx.hash(body.password)
        is_admin = bool(ADMIN_BOOTSTRAP_EMAIL) and body.email.lower().strip() == ADMIN_BOOTSTRAP_EMAIL
        cur.execute(
            "INSERT INTO exe_users (email, password_hash, display_name, is_admin) "
            "VALUES (%s, %s, %s, %s) "
            "RETURNING id, email, display_name, email_verified, is_admin, status, created_at",
            (body.email, password_hash, body.display_name, is_admin),
        )
        user = cur.fetchone()
    conn.commit()

    send_verification_email(str(user["id"]), user["email"])

    return {
        "user": user,
        "message": "Account created — check your email to verify it before logging in",
    }

@app.post("/auth/login")
def login(body: LoginBody, conn=Depends(get_conn)):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, email, display_name, password_hash, email_verified, is_admin, status, created_at "
            "FROM exe_users WHERE email = %s",
            (body.email,),
        )
        user = cur.fetchone()

    if not user or not pwd_ctx.verify(body.password, user["password_hash"]):
        raise HTTPException(401, "Incorrect email or password")

    if user["status"] == "held":
        raise HTTPException(403, "This account is on hold — contact support")
    if user["status"] == "terminated":
        raise HTTPException(403, "This account has been terminated")
    if not user["email_verified"]:
        send_verification_email(str(user["id"]), user["email"])
        raise HTTPException(403, "Your account email needs to be verified — we sent an email to the address associated with this account")

    del user["password_hash"]
    access_token = make_access_token(str(user["id"]), user["email"])
    refresh_token = make_refresh_token(conn, str(user["id"]), body.app)

    return {
        "user": user,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

@app.post("/auth/refresh")
def refresh(body: RefreshBody, conn=Depends(get_conn)):
    token_hash = _hash_refresh_token(body.refresh_token)

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, user_id, app, expires_at, revoked_at FROM exe_refresh_tokens "
            "WHERE token_hash = %s",
            (token_hash,),
        )
        row = cur.fetchone()

        if not row or row["revoked_at"] is not None:
            raise HTTPException(401, "Refresh token is invalid or has been revoked")
        if row["expires_at"] < datetime.now(timezone.utc):
            raise HTTPException(401, "Refresh token has expired — please log in again")

        # Rotation: kill the old one the instant a new one is issued.
        cur.execute(
            "UPDATE exe_refresh_tokens SET revoked_at = now() WHERE id = %s",
            (row["id"],),
        )

        cur.execute("SELECT email, status FROM exe_users WHERE id = %s", (row["user_id"],))
        user_row = cur.fetchone()
    conn.commit()

    if not user_row:
        raise HTTPException(401, "User no longer exists")
    if user_row["status"] == "held":
        raise HTTPException(403, "This account is on hold — contact support")
    if user_row["status"] == "terminated":
        raise HTTPException(403, "This account has been terminated")

    new_access = make_access_token(str(row["user_id"]), user_row["email"])
    new_refresh = make_refresh_token(conn, str(row["user_id"]), row["app"])

    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
    }

@app.post("/auth/logout")
def logout(body: LogoutBody, conn=Depends(get_conn)):
    token_hash = _hash_refresh_token(body.refresh_token)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE exe_refresh_tokens SET revoked_at = now() "
            "WHERE token_hash = %s AND revoked_at IS NULL",
            (token_hash,),
        )
    conn.commit()
    return {"ok": True}

@app.get("/auth/verify-email", response_class=HTMLResponse)
def verify_email(token: str, conn=Depends(get_conn)):
    try:
        user_id = decode_action_token(token, "verify_email")
    except HTTPException as e:
        return VERIFY_PAGE.format(title="Link invalid", message=e.detail, color="#ff6b6b")

    with conn.cursor() as cur:
        cur.execute("UPDATE exe_users SET email_verified = TRUE, updated_at = now() WHERE id = %s", (user_id,))
    conn.commit()
    return VERIFY_PAGE.format(title="Email verified", message="You're all set — you can close this tab and log in now.", color="#7ee89a")

@app.post("/auth/forgot-password")
def forgot_password(body: ForgotPasswordBody, conn=Depends(get_conn)):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, email FROM exe_users WHERE email = %s", (body.email,))
        user = cur.fetchone()
    if user:
        send_password_reset_email(str(user["id"]), user["email"])
    # Always return the same response whether or not the email exists —
    # otherwise this endpoint becomes a way to check who has an account.
    return {"ok": True, "message": "If that email has an account, a reset link was sent"}

@app.post("/auth/reset-password")
def reset_password(body: ResetPasswordBody, conn=Depends(get_conn)):
    user_id = decode_action_token(body.token, "pwd_reset")
    new_hash = pwd_ctx.hash(body.new_password)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE exe_users SET password_hash = %s, updated_at = now() WHERE id = %s",
            (new_hash, user_id),
        )
        # Log out everywhere on password reset — any existing sessions were
        # issued under the old password and shouldn't survive a reset.
        cur.execute(
            "UPDATE exe_refresh_tokens SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL",
            (user_id,),
        )
    conn.commit()
    return {"ok": True, "message": "Password updated — log in again"}

@app.get("/auth/me")
def me(user=Depends(require_user), conn=Depends(get_conn)):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, email, display_name, email_verified, is_admin, status, created_at FROM exe_users WHERE id = %s",
            (user["sub"],),
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "User not found")
    return row

# ─────────────────────────────────────────────────────────────────────────────
# ROUTES — ADMIN
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/admin/users")
def admin_list_users(_=Depends(require_admin), conn=Depends(get_conn)):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, email, display_name, email_verified, is_admin, status, created_at "
            "FROM exe_users ORDER BY created_at DESC"
        )
        return cur.fetchall()

def _set_status(conn, user_id: str, status: str, revoke_sessions: bool):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "UPDATE exe_users SET status = %s, updated_at = now() WHERE id = %s "
            "RETURNING id, email, display_name, status",
            (status, user_id),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "User not found")
        if revoke_sessions:
            cur.execute(
                "UPDATE exe_refresh_tokens SET revoked_at = now() WHERE user_id = %s AND revoked_at IS NULL",
                (user_id,),
            )
    conn.commit()
    return row

@app.post("/admin/users/{user_id}/hold")
def admin_hold_user(user_id: str, _=Depends(require_admin), conn=Depends(get_conn)):
    return _set_status(conn, user_id, "held", revoke_sessions=True)

@app.post("/admin/users/{user_id}/unhold")
def admin_unhold_user(user_id: str, _=Depends(require_admin), conn=Depends(get_conn)):
    return _set_status(conn, user_id, "active", revoke_sessions=False)

@app.post("/admin/users/{user_id}/terminate")
def admin_terminate_user(user_id: str, _=Depends(require_admin), conn=Depends(get_conn)):
    return _set_status(conn, user_id, "terminated", revoke_sessions=True)

@app.delete("/admin/users/{user_id}")
def admin_delete_user(user_id: str, _=Depends(require_admin), conn=Depends(get_conn)):
    with conn.cursor() as cur:
        cur.execute("DELETE FROM exe_users WHERE id = %s", (user_id,))
        deleted = cur.rowcount
    conn.commit()
    if not deleted:
        raise HTTPException(404, "User not found")
    return {"ok": True}

# ─────────────────────────────────────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok"}
