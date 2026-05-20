# Security Policy

## Reporting a vulnerability

Please report security issues privately. Do not open public GitHub issues for vulnerabilities.

Contact: replace this line with your security contact email or PGP key.

We aim to acknowledge within 72 hours and provide a fix or workaround within 14 days for confirmed issues.

## Threat model

Vexa is intended to run as a **local single-user tool** on the analyst's workstation. It is not designed for multi-tenant or internet-facing deployment.

### In scope

- Authentication bypass against the local web UI
- Path traversal in any endpoint that accepts a path or scan ID
- CSRF or session-fixation attacks against the local UI
- Injection (command, template, XSS) in any endpoint
- Memory exhaustion / DoS via crafted uploaded files
- Disclosure of one user's scan data to another (for shared multi-user installs)

### Out of scope

- Vulnerabilities that require write access to the host filesystem (you can already replace the binary)
- Vulnerabilities requiring physical or root access to the host
- Issues in third-party tools (androguard, FastAPI, Frida, etc.) — please report those upstream
- Findings produced by the analysis itself (these are intentional outputs, not bugs)

## Security controls

### Authentication
- First-run setup wizard creates the administrator account. There are **no default credentials**.
- Passwords are stored hashed using PBKDF2-HMAC-SHA256 with 600 000 iterations and a 16-byte random salt.
- Login attempts are rate-limited per source IP: 5 failed attempts trigger a 15-minute lockout.
- Failed login responses do not distinguish between "user not found" and "wrong password" (no user enumeration).

### Sessions
- Sessions are 32-byte URL-safe random tokens stored in memory.
- Default session lifetime is 8 hours.
- Cookies are set with `HttpOnly`, `SameSite=Strict`, and `Secure` (when serving over HTTPS).

### CSRF
- A separate per-session CSRF token is issued at login.
- All state-changing requests (`POST` / `PUT` / `PATCH` / `DELETE`) require the token in the `X-Vexa-Csrf` header.
- The token rotates on every login.

### Input handling
- `scan_id` values must match `^[a-zA-Z0-9_-]{8,64}$` and the resolved file path must remain inside the reports directory.
- Stored binary paths (`apk_path` / `ipa_path`) are re-validated against the upload directory on every read.
- Chat input is capped at 4 000 characters per message and 100 messages per conversation.
- Upload size is capped at 512 MB.

### Error handling
- Production error responses do not include stack traces or local file paths.
- Full tracebacks are written to the server log only.
- The OpenAPI / Swagger UI is disabled.

### Outbound network
- Outbound HTTPS is restricted to specific opt-in flows (store-URL fetch, Ollama on loopback).
- No telemetry. No remote logging. No automatic update check.

### Dependencies
- Pinned in `requirements.txt`.
- Update via `pip install -U -r requirements.txt` and review release notes.

## Things you should still do

- Run Vexa on a non-public interface (default bind is `127.0.0.1`).
- If exposing on a LAN, place behind a TLS-terminating reverse proxy (nginx, Caddy).
- Keep your administrator password strong; the password complexity check is a minimum, not a goal.
- Treat the contents of `vexa_data/uploads/` as sensitive — these are the apps you are analysing.
- Treat scan reports as sensitive — they contain extracted secrets and exploitation paths.
