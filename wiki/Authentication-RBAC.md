# 🔐 Authentication & RBAC

*Every login is checked twice: once to prove who you are, once to decide what you're allowed to touch.*

Login/session/TOTP/WebAuthn/LDAP/OIDC/rate-limiting/API-token machinery
is **copied from debcontrol nearly unchanged** — see that project's own
wiki for the exhaustive version (session rows vs. signed cookies,
brute-force lockout, TOTP recovery codes, the WebAuthn ceremony, OIDC's
own session, the bootstrap script). What's genuinely different here is
the authorization model on top of it.

## No accounts are ever auto-created

Every `User` row is created inside this app first
(`scripts/create_admin.py` for the first superadmin, the Users page
after that) — never by LDAP or OIDC. `auth_provider` only decides *how*
an existing account proves who it is.

## RBAC: company memberships + access level, not roles

Still no custom roles — but not single-company either. Every user is
either:

- **A superadmin** (`User.is_superadmin = True`) — no memberships at
  all. Sees and manages every company.
- **A company user** — zero or more `CompanyMembership` rows, each
  naming one `Company` and one `AccessLevel` (`READ` or `READ_WRITE`),
  independent per company. The same person can be `READ_WRITE` at one
  company and `READ`-only at another. Zero memberships means logged in
  but scoped to nothing.

Enforced at two independent layers:

- **`require_write`** — is this user allowed to write *at all*
  (superadmin, or `READ_WRITE` on **at least one** company)? The generic
  nav-level gate for pages not scoped to one company (Initialize,
  Scheduling's landing page).
- **`ensure_company_access(user, company_id, write=...)`** /
  **`visible_company_ids(user)`** — *which* company/companies' data may
  they touch (a set, not a single id — `None` for a superadmin means "no
  filter")? **Out-of-scope reads 404, never 403** — a 403 would itself
  confirm the company/honeypot exists, which an outsider shouldn't
  learn for free.

No per-honeypot grant, no custom-role editor — see `app/db/models/
user.py`'s docstring for why this is deliberately flatter than
debcontrol's `Role`/`Permission` matrix.

**What a `READ` company user sees today**: Dashboard, the Honeypots
list, and per honeypot — Overview, Monitoring, Activity (read-only:
what OpenCanary caught, no management implied). Scheduling, `/api`, and
a honeypot's Updates/Terminal/Logs/Config/Settings tabs are all
write-tier — hidden from nav and `403` if reached directly.
`READ_WRITE` gets all of it.

## Sessions, TOTP, WebAuthn, API tokens, OIDC, rate limiting

Unchanged in mechanism from debcontrol — `UserSession` rows (not signed
cookies), self-service TOTP with recovery codes, WebAuthn/passkeys,
per-user API tokens (prefixed `hhpat_`) scoped to whatever the owning
account currently permits, the same per-IP login rate limiter. One
simplification: **no per-role mandatory TOTP** (there are no roles) —
TOTP/passkeys are purely self-service; a fleet-wide "require 2FA"
toggle would live on `AppSettings` instead.

WebAuthn's origin check and OIDC's `redirect_uri` both need
`request.url.scheme` to be correct — behind a TLS-terminating reverse
proxy, that needs `ProxyHeadersMiddleware` to have fixed it from
`X-Forwarded-Proto` first, or both fail with "Unexpected client data
origin". See [Installation](Installation.md) for `TRUSTED_PROXY_IPS`.

**Login is two steps**: `GET /login` collects only the username (plus
an OIDC button if enabled, labeled with `AppSettings.oidc_provider_name`
if set), then `/login/password?username=...` offers a passkey *or* a
password — a passkey signs straight in, no password ever submitted,
the same GitHub/Google-style flow. The passkey button always shows on
step two regardless of whether the account has one or even exists
(enumeration-resistance — a nonexistent username and a real one with no
passkey get an identical error).

**Real client IP behind a proxy.** Audit logging and the rate limiter
both read `request.client.host` — correct only if the proxy shares this
app's network namespace. `TRUST_FORWARDED_FOR` (off by default) tells
`ProxyHeadersMiddleware` to also trust `X-Forwarded-For` — off by
default because trusting it from anyone lets an attacker spoof a new
"source" every attempt and defeat the rate limiter entirely. Only turn
it on once `TRUSTED_PROXY_IPS` is narrowed to your real proxy.

## Impersonate: a superadmin signing in as another account

`POST /users/{id}/impersonate` (Users list, "Sign in as") — for support/
debugging, a superadmin can take over another account's session without
knowing their password. Ported from an identical debcontrol feature
(`user.impersonate`, its own permission there); this app has no roles/
permissions at all, so the whole `app.web.routes.impersonation` router
is gated simply on "you must already be a superadmin," and the
guardrail against admin-on-admin impersonation becomes "the target may
never itself be a superadmin."

Mechanism: starting an impersonation does **not** touch the superadmin's
own session row — it creates a brand-new `UserSession` for the target
account (`UserSession.impersonator_id` tags who started it), swaps the
browser's session cookie over to that new session, and stashes the
superadmin's own raw session token in a second, signed, httponly cookie
(`impersonation_return`) so it can be handed back later. "Logging out" of
an impersonated session (the same `/logout` route, no separate endpoint)
restores the superadmin's own session instead of a full sign-out — like
closing a `su` shell — falling back to an ordinary logout only if that
return cookie is missing/expired or the original session no longer
validates.

Guardrails: can't impersonate yourself, can't impersonate a disabled
account, can't impersonate another superadmin (no chains). Every start/
stop is its own audit log entry naming both accounts; actions taken
during the impersonated session are audit-logged as usual under the
impersonated account. The topbar shows the impersonated account's name
with the superadmin's own name in a colored tag so it's never ambiguous
who "you" are while it's active.

Deliberately web-only, not in the REST API — swapping a session cookie
has no meaningful translation to a stateless bearer-token call, which
already scopes to one fixed account by design.
