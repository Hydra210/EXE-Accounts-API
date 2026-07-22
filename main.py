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
from fastapi.staticfiles import StaticFiles
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
TWO_FACTOR_CODE_MINUTES = 10

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

# Serves the /icons folder at <API_URL>/icons/... — needed so email clients
# (which can't load local repo files) can actually fetch icon.png over HTTPS.
_icons_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")
if os.path.isdir(_icons_dir):
    app.mount("/icons", StaticFiles(directory=_icons_dir), name="icons")

# Used as the <img src> in emails. Falls back to relative /icons/icon.png if
# PUBLIC_APP_URL isn't set, which won't load in an inbox — set that env var.
EMAIL_ICON_URL = f"{PUBLIC_APP_URL}/icons/icon.png" if PUBLIC_APP_URL else "/icons/icon.png"

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

class Verify2FABody(BaseModel):
    challenge_token: str
    code: str

class Toggle2FABody(BaseModel):
    enabled: bool

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
# 2FA HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _hash_code(code: str) -> str:
    # Same principle as password/refresh-token storage — only the hash lives in the DB.
    return hashlib.sha256(code.encode()).hexdigest()

def make_2fa_challenge_token(user_id: str, app_name: Optional[str]) -> str:
    # A short-lived token that stands in for "this person already proved their
    # password" so the code-entry step doesn't need to re-send it. Carries the
    # app name through so the eventual refresh token is still tagged correctly.
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id, "kind": "2fa_login", "app": app_name,
        "iat": now, "exp": now + timedelta(minutes=TWO_FACTOR_CODE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def decode_2fa_challenge(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.ExpiredSignatureError:
        raise HTTPException(400, "This login attempt has expired — log in again")
    except jwt.InvalidTokenError:
        raise HTTPException(400, "Invalid login session — log in again")
    if payload.get("kind") != "2fa_login":
        raise HTTPException(400, "Invalid login session — log in again")
    return payload

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
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
            # urllib's default User-Agent ("Python-urllib/3.x") gets flagged as a bot
            # and blocked by Cloudflare (sitting in front of api.resend.com) before the
            # request ever reaches Resend — a normal-looking UA avoids that.
            "User-Agent": "Mozilla/5.0 (compatible; exe-accounts-api/1.0)",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        # Resend puts the real reason in the response body — the status code alone
        # ("403 Forbidden") could mean an invalid key, an unverified domain, or the
        # testing-only sandbox restriction, so surface the body to tell them apart.
        detail = e.read().decode(errors="replace")
        print(f"[mailer] failed to send to {to}: HTTP {e.code} — {detail}")
    except Exception as e:
        # Best-effort — a failed email shouldn't take down register/login.
        print(f"[mailer] failed to send to {to}: {e}")

# Shared visual language across all transactional emails: dark card, small
# uppercase "SENTINEL" wordmark, monochrome CTA button, muted footer.
# Inline styles only + safe font stacks — most email clients strip <link>
# stylesheets, so this can't actually load Syne/Outfit/DM Mono, it just
# mimics their proportions with system fonts.
EMAIL_HEADER = """<tr><td style="background:#000000;padding:32px 20px;text-align:center;">
  <img src=\"""" + EMAIL_ICON_URL + """\" alt="EXE" width="34" height="34" style="display:inline-block;border-radius:7px;">
</td></tr>"""

EMAIL_SAFETY = """<tr><td style="padding:8px 0 0;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid rgba(255,255,255,0.08);margin-top:12px;">
  <tr><td style="padding:28px 0 0;">
    <p style="font-family:'Courier New',monospace;color:rgba(232,232,232,0.35);font-size:10.5px;letter-spacing:2px;text-transform:uppercase;margin:0 0 14px;">Account Safety</p>
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
      <tr><td style="padding:0 0 10px;vertical-align:top;width:18px;"><span style="font-family:Helvetica,Arial,sans-serif;color:rgba(232,232,232,0.3);font-size:13px;">—</span></td>
          <td style="padding:0 0 10px;"><p style="font-family:Helvetica,Arial,sans-serif;color:rgba(232,232,232,0.45);font-size:12.5px;line-height:1.6;margin:0;">EXE staff will never ask for your password, 2FA code, or ask you to move funds or items to "verify" an account.</p></td></tr>
      <tr><td style="padding:0 0 10px;vertical-align:top;width:18px;"><span style="font-family:Helvetica,Arial,sans-serif;color:rgba(232,232,232,0.3);font-size:13px;">—</span></td>
          <td style="padding:0 0 10px;"><p style="font-family:Helvetica,Arial,sans-serif;color:rgba(232,232,232,0.45);font-size:12.5px;line-height:1.6;margin:0;">Always check that links point to a domain you recognize before entering your credentials.</p></td></tr>
      <tr><td style="padding:0;vertical-align:top;width:18px;"><span style="font-family:Helvetica,Arial,sans-serif;color:rgba(232,232,232,0.3);font-size:13px;">—</span></td>
          <td style="padding:0;"><p style="font-family:Helvetica,Arial,sans-serif;color:rgba(232,232,232,0.45);font-size:12.5px;line-height:1.6;margin:0;">Didn't request this? Ignore this email — no changes will be made to your account.</p></td></tr>
    </table>
  </td></tr>
  </table>
</td></tr>"""

EMAIL_FOOTER = """<tr><td style="padding:32px 0 0;border-top:1px solid rgba(255,255,255,0.08);margin-top:28px;">
  <p style="font-family:Helvetica,Arial,sans-serif;font-size:11px;line-height:1.6;color:rgba(232,232,232,0.28);margin:0;">
    This is an automated message from EXE Account Services — replies to this address aren't monitored.
  </p>
</td></tr>"""

EMAIL_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#050505;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#050505;">
""" + EMAIL_HEADER + """
<tr><td align="center" style="padding:44px 20px 56px;">
<table role="presentation" width="460" cellpadding="0" cellspacing="0" style="max-width:460px;width:100%;">
<tr><td>
  <p style="font-family:'Courier New',monospace;color:rgba(232,232,232,0.35);font-size:10.5px;letter-spacing:2px;text-transform:uppercase;margin:0 0 14px;">{eyebrow}</p>
  <h1 style="font-family:Helvetica,Arial,sans-serif;color:#f5f5f5;font-size:22px;font-weight:700;letter-spacing:0.2px;margin:0 0 14px;">{title}</h1>
  <p style="font-family:Helvetica,Arial,sans-serif;color:rgba(232,232,232,0.55);font-size:14px;line-height:1.6;margin:0 0 28px;">{message}</p>
  <table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="border-radius:7px;background:#f2f2f2;">
    <a href="{link}" style="display:inline-block;color:#0a0a0a;padding:13px 30px;text-decoration:none;font-family:Helvetica,Arial,sans-serif;font-weight:700;letter-spacing:1px;font-size:12px;text-transform:uppercase;">{button_label}</a>
  </td></tr></table>
  <p style="font-family:'Courier New',monospace;color:rgba(232,232,232,0.25);font-size:11px;line-height:1.6;margin:28px 0 0;word-break:break-all;">If the button doesn't work, paste this link into your browser:<br>{link}</p>
</td></tr>
""" + EMAIL_SAFETY + EMAIL_FOOTER + """
</table>
</td></tr>
</table>
</body></html>"""

def send_verification_email(user_id: str, email: str) -> None:
    token = make_action_token(user_id, "verify_email", minutes=60 * 24)
    link = f"{PUBLIC_APP_URL}/auth/verify-email?token={token}" if PUBLIC_APP_URL else f"(set PUBLIC_APP_URL) /auth/verify-email?token={token}"
    html = EMAIL_TEMPLATE.format(
        eyebrow="Account Verification",
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
  .spinner {{ width:32px; height:32px; margin:0 auto 22px; border-radius:50%;
              border:3px solid rgba(255,255,255,0.12); border-top-color:rgba(255,255,255,0.6);
              animation: spin 0.8s linear infinite; }}
  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
  .result {{ opacity:0; transition: opacity 0.35s ease; }}
  .result.show {{ opacity:1; }}
  h1 {{ font-size:20px; letter-spacing:1px; margin-bottom:10px; color:{color}; }}
  p {{ font-size:14px; color:rgba(232,232,232,0.6); }}
</style></head>
<body>
  <div class="box">
    <div class="spinner" id="spinner"></div>
    <div class="result" id="result"><h1>{title}</h1><p>{message}</p></div>
  </div>
  <script>
    setTimeout(function () {{
      document.getElementById('spinner').style.display = 'none';
      document.getElementById('result').classList.add('show');
    }}, 900);
  </script>
</body></html>"""

def send_password_reset_email(user_id: str, email: str) -> None:
    token = make_action_token(user_id, "pwd_reset", minutes=60)
    link = f"{PUBLIC_APP_URL}/reset-password?token={token}" if PUBLIC_APP_URL else f"(set PUBLIC_APP_URL) /reset-password?token={token}"
    html = EMAIL_TEMPLATE.format(
        eyebrow="Password Reset",
        title="Reset your EXE account password",
        message="Click below to reset your password. This link expires in 1 hour. If you didn't request this, ignore this email.",
        link=link, button_label="RESET PASSWORD",
    )
    send_email(email, "Reset your EXE account password", html)

RESET_PAGE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Reset Password</title>
<style>
  body {{ background:#0a0a0a; color:#e8e8e8; font-family:sans-serif; display:flex;
          align-items:center; justify-content:center; height:100vh; margin:0; }}
  .box {{ text-align:center; max-width:340px; width:100%; padding:32px; box-sizing:border-box; }}
  h1 {{ font-size:18px; letter-spacing:1px; margin:0 0 18px; }}
  input {{ width:100%; box-sizing:border-box; background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.15);
           color:#fff; padding:10px 12px; border-radius:6px; font-size:13px; margin-bottom:10px; outline:none; }}
  button {{ width:100%; background:rgba(255,255,255,0.1); border:1px solid rgba(255,255,255,0.25); color:#fff;
            padding:10px; border-radius:6px; font-weight:700; letter-spacing:1px; font-size:12px; cursor:pointer; text-transform:uppercase; }}
  button:hover {{ background:rgba(255,255,255,0.16); }}
  p.msg {{ font-size:13px; color:rgba(232,232,232,0.6); margin:14px 0 0; min-height:16px; }}
  p.msg.err {{ color:#ff6b6b; }}
  p.msg.ok {{ color:#7ee89a; }}
</style></head>
<body>
  <div class="box">
    <h1>Reset your password</h1>
    <input id="pw" type="password" placeholder="New password">
    <input id="pw2" type="password" placeholder="Confirm new password">
    <button onclick="submitReset()">Reset Password</button>
    <p class="msg" id="msg"></p>
  </div>
  <script>
    const RESET_TOKEN = {token_json};
    async function submitReset() {{
      const pw = document.getElementById('pw').value;
      const pw2 = document.getElementById('pw2').value;
      const msg = document.getElementById('msg');
      msg.className = 'msg';
      if (!pw || pw.length < 8) {{ msg.className = 'msg err'; msg.textContent = 'Password must be at least 8 characters.'; return; }}
      if (pw !== pw2) {{ msg.className = 'msg err'; msg.textContent = 'Passwords do not match.'; return; }}
      try {{
        const res = await fetch('/auth/reset-password', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ token: RESET_TOKEN, new_password: pw }}),
        }});
        const data = await res.json().catch(() => ({{}}));
        if (!res.ok) throw new Error(data.detail || 'Reset failed');
        msg.className = 'msg ok';
        msg.textContent = 'Password updated — you can close this tab and log in.';
        document.getElementById('pw').disabled = true;
        document.getElementById('pw2').disabled = true;
      }} catch (e) {{
        msg.className = 'msg err';
        msg.textContent = e.message;
      }}
    }}
  </script>
</body></html>"""

CODE_EMAIL_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#050505;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#050505;">
""" + EMAIL_HEADER + """
<tr><td align="center" style="padding:44px 20px 56px;">
<table role="presentation" width="460" cellpadding="0" cellspacing="0" style="max-width:460px;width:100%;">
<tr><td>
  <p style="font-family:'Courier New',monospace;color:rgba(232,232,232,0.35);font-size:10.5px;letter-spacing:2px;text-transform:uppercase;margin:0 0 14px;">Login Verification</p>
  <h1 style="font-family:Helvetica,Arial,sans-serif;color:#f5f5f5;font-size:22px;font-weight:700;letter-spacing:0.2px;margin:0 0 14px;">Your login code</h1>
  <p style="font-family:Helvetica,Arial,sans-serif;color:rgba(232,232,232,0.55);font-size:14px;line-height:1.6;margin:0 0 26px;">Enter this code to finish signing in to your EXE account.</p>
  <p style="font-family:'Courier New',monospace;font-size:36px;font-weight:700;letter-spacing:12px;color:#fff;margin:0 0 26px;">{code}</p>
  <p style="font-family:Helvetica,Arial,sans-serif;color:rgba(232,232,232,0.3);font-size:11px;line-height:1.6;margin:24px 0 0;">Expires in {minutes} minutes.<br>If this wasn't you, you can safely ignore this email.</p>
</td></tr>
""" + EMAIL_SAFETY + EMAIL_FOOTER + """
</table>
</td></tr>
</table>
</body></html>"""

def send_login_code_email(email: str, code: str) -> None:
    html = CODE_EMAIL_TEMPLATE.format(code=code, minutes=TWO_FACTOR_CODE_MINUTES)
    send_email(email, "Your EXE login code", html)

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
            "SELECT id, email, display_name, password_hash, email_verified, is_admin, status, "
            "created_at, two_factor_enabled FROM exe_users WHERE email = %s",
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

    if user["two_factor_enabled"]:
        code = f"{secrets.randbelow(1_000_000):06d}"
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=TWO_FACTOR_CODE_MINUTES)
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO exe_login_codes (user_id, code_hash, expires_at) VALUES (%s, %s, %s)",
                (str(user["id"]), _hash_code(code), expires_at),
            )
        conn.commit()
        send_login_code_email(user["email"], code)
        challenge_token = make_2fa_challenge_token(str(user["id"]), body.app)
        return {
            "requires_2fa": True,
            "challenge_token": challenge_token,
            "message": "We sent a login code to your email",
        }

    del user["password_hash"]
    access_token = make_access_token(str(user["id"]), user["email"])
    refresh_token = make_refresh_token(conn, str(user["id"]), body.app)

    return {
        "user": user,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

@app.post("/auth/verify-2fa")
def verify_2fa(body: Verify2FABody, conn=Depends(get_conn)):
    payload = decode_2fa_challenge(body.challenge_token)
    user_id = payload["sub"]
    submitted_hash = _hash_code(body.code.strip())

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, code_hash FROM exe_login_codes WHERE user_id = %s AND consumed_at IS NULL "
            "AND expires_at > now() ORDER BY created_at DESC LIMIT 1",
            (user_id,),
        )
        row = cur.fetchone()
        if not row or not secrets.compare_digest(row["code_hash"], submitted_hash):
            raise HTTPException(400, "Incorrect or expired code")

        cur.execute("UPDATE exe_login_codes SET consumed_at = now() WHERE id = %s", (row["id"],))
        cur.execute(
            "SELECT id, email, display_name, email_verified, is_admin, status, created_at, "
            "two_factor_enabled FROM exe_users WHERE id = %s",
            (user_id,),
        )
        user = cur.fetchone()
    conn.commit()

    if not user:
        raise HTTPException(404, "User not found")

    access_token = make_access_token(str(user["id"]), user["email"])
    refresh_token = make_refresh_token(conn, str(user["id"]), payload.get("app"))

    return {
        "user": user,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

@app.post("/auth/2fa/toggle")
def toggle_2fa(body: Toggle2FABody, user=Depends(require_user), conn=Depends(get_conn)):
    # Lets a consuming site expose an account-settings toggle. The admin panel
    # doesn't have a settings screen, so it never calls this — 2FA just stays
    # on by default there.
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "UPDATE exe_users SET two_factor_enabled = %s, updated_at = now() WHERE id = %s "
            "RETURNING id, two_factor_enabled",
            (body.enabled, user["sub"]),
        )
        row = cur.fetchone()
    conn.commit()
    if not row:
        raise HTTPException(404, "User not found")
    return row

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
    return VERIFY_PAGE.format(title="Verified successfully", message="You're all set — you can close this tab and log in now.", color="#7ee89a")

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

@app.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(token: str):
    return RESET_PAGE.format(token_json=json.dumps(token))

@app.get("/auth/me")
def me(user=Depends(require_user), conn=Depends(get_conn)):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, email, display_name, email_verified, is_admin, status, created_at, "
            "two_factor_enabled FROM exe_users WHERE id = %s",
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
