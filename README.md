# EXE Account API

Centralized auth for the EXE Development brand. Sentinel connects to this,
and anything else you build later can too — same account, same login,
everywhere.

## How it works

- **Register/login** → returns an `access_token` (JWT, expires in 15 min)
  and a `refresh_token` (opaque random string, expires in 30 days)
- **Access token** goes on every request as `Authorization: Bearer <token>`
- **Refresh token** gets traded in at `/auth/refresh` for a new pair when the
  access token expires — this is what makes "log in once, stay logged in for
  weeks" work instead of re-logging-in every 15 minutes
- Every refresh **rotates** the token — the old refresh token dies the moment
  a new one is issued. If a leaked/stolen refresh token ever gets reused
  after the real client already refreshed, it'll fail — that's the signal
  something's wrong, not a bug.

## Endpoints

| Method | Path            | Body                                  | Auth      |
|--------|-----------------|----------------------------------------|-----------|
| POST   | `/auth/register`| `{email, password, display_name, app}` | none      |
| POST   | `/auth/login`   | `{email, password, app}`               | none      |
| POST   | `/auth/refresh` | `{refresh_token}`                      | none      |
| POST   | `/auth/logout`  | `{refresh_token}`                      | none      |
| GET    | `/auth/me`      | —                                       | Bearer access token |
| GET    | `/auth/verify-email?token=` | —                          | none (token in query string) |
| POST   | `/auth/forgot-password` | `{email}`                      | none      |
| POST   | `/auth/reset-password`  | `{token, new_password}`        | none      |
| GET    | `/admin/users`  | —                                       | Bearer (admin only) |
| POST   | `/admin/users/{id}/hold` | —                             | Bearer (admin only) |
| POST   | `/admin/users/{id}/unhold` | —                           | Bearer (admin only) |
| POST   | `/admin/users/{id}/terminate` | —                        | Bearer (admin only) |
| DELETE | `/admin/users/{id}` | —                                  | Bearer (admin only) |

`app` is optional — pass a string like `"sentinel-desktop"` or `"sentinel-web"`
so you can tell in the DB which client issued which session. Not required.

**Account status:** every account is `active`, `held`, or `terminated`.
`held`/`terminated` accounts can't log in or refresh their session — holding
or terminating someone also immediately revokes every refresh token they
have, so it takes effect within 15 minutes at the absolute worst (however
long their current access token has left) rather than needing them to log
out.

## Becoming an admin

There's no admin-signup flow on purpose — the **first account registered
with the email set in `ADMIN_BOOTSTRAP_EMAIL`** is automatically promoted to
admin on registration. Set that env var to your own email before you
register your first account, then register normally through
`/auth/register`. Every other admin after that, promote manually via SQL:
```sql
UPDATE exe_users SET is_admin = TRUE WHERE email = 'someone@example.com';
```

## Admin panel

`admin-panel.html` is a single, no-build-step file — just open it directly
in a browser (double-click it, or drag it into a browser tab). Log in with
your admin account and API URL, and you get a table of every registered
account with Hold / Unhold / Terminate / Delete buttons. It's not meant to
be hosted publicly — it's just for you, locally.

## Email (verification + password reset)

Using a Gmail account as the mailer for now, until there's a proper
transactional email provider:

1. Turn on 2-Step Verification on the Google account you're sending from
   (required before Google will issue App Passwords)
2. Generate an **App Password** at
   [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
   — this is a 16-character password just for this app, not your real Google
   password
3. Set these env vars:
   - `SMTP_USER` — the Gmail address itself
   - `SMTP_PASSWORD` — the App Password from step 2
   - `MAIL_FROM` — usually the same as `SMTP_USER`
   - `PUBLIC_APP_URL` — base URL people click through to (defaults to this
     API's own URL if unset, which is fine for now since there's no
     dedicated frontend for these links yet — they just show raw JSON when
     clicked)

If `SMTP_USER`/`SMTP_PASSWORD` aren't set, the API doesn't fail — it just
logs `[mailer] SMTP not configured — skipping email` and moves on, so you
can develop without email working at all if you want.

## Setting it up

1. **Create a Postgres database** (a new one on Render works — keep it
   separate from Sentinel's DB since this is a different service with its
   own data, even though it's the same underlying account system Sentinel
   will read from)
2. Run `schema.sql` against it once:
   ```
   psql "$DATABASE_URL" -f schema.sql
   ```
3. **Generate a JWT secret** — this signs every access token, so it needs to
   be long and random, not something memorable:
   ```
   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
4. Set both as environment variables (locally via `.env`, or in Render's
   dashboard under Environment):
   - `DATABASE_URL`
   - `JWT_SECRET`
   - `ADMIN_BOOTSTRAP_EMAIL` — your email, so your first registration becomes admin
   - `SMTP_USER`, `SMTP_PASSWORD`, `MAIL_FROM` — see the Email section below
     (optional to start — the API works fine without these, it just won't
     send emails)

## Deploying on Render (same setup as Sentinel)

1. New Render **Web Service**, point it at this repo
2. Build command: `pip install -r requirements.txt`
3. Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Add the two environment variables above in Render's dashboard
5. Once it's live you'll have a URL like `https://exe-accounts-xyz.onrender.com`

## Wiring Sentinel's desktop login gate up to this

Right now Sentinel desktop's login gate posts to
`{SENTINEL_API_ORIGIN}/sentinel/api/exe/auth/login` — a placeholder route on
Sentinel's own backend that doesn't exist. Once this service is deployed,
point the gate directly at **this** service instead of Sentinel's backend:

```js
const res = await fetch('https://exe-accounts-xyz.onrender.com/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password, app: 'sentinel-desktop' }),
});
const data = await res.json();
// data.access_token, data.refresh_token, data.user
```

Store `access_token` in memory (it's short-lived, no big deal if it's lost on
restart) and `refresh_token` somewhere it survives app restarts — for the
desktop app specifically, the right place is the OS keychain via Tauri's
Rust side (the `keyring` crate), not `localStorage`/`sessionStorage`, since
those aren't available in Tauri's webview anyway and wouldn't be secure even
if they were.

**This part's already done** — see `sentinel-desktop`'s login gate + Rust
`auth_store.rs`, which does exactly this (real login call, keychain-stored
refresh token, silent re-login on launch).

## Getting Sentinel's own backend to recognize these accounts (web + desktop)

Right now, only the *client* (desktop app) knows who's logged in — Sentinel's
FastAPI backend has no idea, since it just gets normal requests with no
identity attached. To make Sentinel's backend actually check "is this a
real, logged-in, non-terminated EXE account" before handling a request, it
needs to verify the access token itself. Two ways to do that:

**Option A — shared secret (recommended for two services you own):**
Give Sentinel's backend the exact same `JWT_SECRET` env var as this service,
and it can verify tokens locally with zero network calls — fastest, and
totally fine since you control both codebases:

```python
# In Sentinel's main.py
import jwt
from fastapi import Header, HTTPException

JWT_SECRET = os.environ["JWT_SECRET"]  # same value as exe-accounts-api

def require_exe_account(authorization: str = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Access token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid access token")

# Then on any route that needs a logged-in user:
@app.get("/sentinel/api/whatever")
def whatever(user=Depends(require_exe_account)):
    # user["sub"] is the EXE account's user id, user["email"] is their email
    ...
```
This only tells you the token is *valid* (right signature, not expired) —
it doesn't re-check `held`/`terminated` status, since that lives in the
other service's DB. Good enough for most routes; for anything sensitive,
pair it with a periodic call to `/auth/me` on this service instead (Option B).

**Option B — ask this service directly (token introspection):**
Sentinel's backend calls `GET {this_service}/auth/me` with the same bearer
token on each request. Slower (one extra network hop per request) but
always reflects the account's *current* status (catches a hold/termination
immediately, not just at token expiry) since it hits the real DB every time.

Most setups use Option A for speed and only reach for Option B on routes
where an immediate hold/terminate needs to take effect mid-session.

**The web dashboard specifically** still needs its own login page built —
right now it only has the profile-card selector, no EXE account login UI at
all. That's a real chunk of frontend work (new login/register screens,
deciding how the browser stores the refresh token, since cookies vs. token-
in-memory work differently in a browser tab that closes vs. a desktop app
that keeps running) — flag it when you're ready to tackle it and we'll
figure out the storage side properly rather than bolting it on.

## What's not built yet (on purpose, keeping this first pass focused)

- **Rate limiting on login/register** — nothing stopping brute-force attempts
  right now. Worth adding before this is public-facing.
- **Web dashboard login UI** — see note above.
