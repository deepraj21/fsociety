# 03b — Authentication, credentials & gateway bypass (A07/A01:2025 · WSTG-ATHN/ATHZ/SESS)

This is the "bypass their gateways" catalog. **Active-phase file** — Phase 0 gate
applies: localhost target + explicit user confirmation + bounded, non-destructive tests.

## 1. Credential testing (the dictionary-attack lane)

Order matters — cheap proofs first:

1. **Default credentials** (WSTG-ATHN-02): check repo/config/docs for defaults
   (`admin:admin`, `root:root`, `test:test`), vendor defaults (grafana, phpMyAdmin…).
   Probe them once against localhost login.
2. **Hardcoded credentials** (CWE-798): grep `.env*`, config, docker-compose,
   test fixtures (`password=`, `passwd:`, `secret:`).
3. **Bounded dictionary attack** (WSTG-ATHN-03 lockout evaluation):
   ```bash
   # Caps are hard requirements — never raise them without user instruction:
   #   ≤ wordlist length (80) · ≥1s delay · stop on FIRST lockout signal · local only
   while read -r pw; do
     code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:PORT/login \
            -H 'Content-Type: application/json' \
            -d "{\"username\":\"admin\",\"password\":\"$pw\"}")
     echo "try → $code"
     [ "$code" = "429" ] && { echo "LOCKOUT DETECTED — stopping"; break; }
     sleep 1
   done < skills/mr-robot/scripts/wordlist-common-passwords.txt
   ```
   **Findings from the run:** was `admin` protected by a strong password? (no = high);
   was there *no lockout/rate limit*? (no = medium-high, A07:2025); does the response
   differ for unknown-user vs wrong-password? (= enumeration, low-medium).
4. **Password policy** (static): min length, complexity rules, breach-list checks in
   register/reset flows; `HaveIBeenPwned` k-anonymity usage.
5. **Reset flow** (WSTG-ATHN-09): token entropy, expiry, single-use, host-header-poisoned
   reset links, response discloses account existence.

## 2. Authentication bypass (WSTG-ATHN-04)

- **JWT** (WSTG-SESS-10): `alg:none` (strip signature / set `none`), RS256→HS256 key
  confusion (sign with the public key), `kid` path/traversal to a known file, weak/blank
  secrets (`jwt_tool -C -d wordlist` bounded), `exp`/`nbf` tampering, `aud`/`iss` not checked.
  Static check: grep `verify=False`, `algorithms` not pinned, secrets in config.
- **Session** (WSTG-SESS-01..11): missing HttpOnly/Secure/SameSite, session fixation
  (pre-auth id accepted post-login), predictable ids, no timeout, logout doesn't invalidate,
  concurrent sessions allowed when policy says otherwise.
- **OAuth/OIDC** (WSTG-ATHZ-05): `state` missing/fixable, redirect_uri open-match, token
  audience not validated, PKCE skipped on public clients.
- **MFA** (WSTG-ATHN-11): bypassable via `?mfa=0`, backup-code reuse, 2FA only on first step.
- **Header auth:** `X-User: admin` trusted when behind a proxy that's not stripping it —
  classic gateway bypass: send `X-Forwarded-For/Host` overrides and watch access change.

## 3. Authorization / privilege escalation (WSTG-ATHZ · API5 BFLA · API1 BOLA)

Two-account methodology (create both locally):

- **Horizontal (IDOR, CWE-639, MITRE #24):** as user A, fetch/modify `/orders/{B's id}` —
  change one id at a time (sequential + UUID-guessable). Object-level check missing → **high**.
- **Vertical (BFLA):** as normal user hit admin routes: `PATCH /users/{id}/role`,
  `/admin/*`, method override (`X-HTTP-Method-Override: DELETE`), verb tampering
  (GET vs POST on state-changing endpoints — WSTG-CONF-06).
- **Path bypass:** `/admin` → `/Admin`, `//admin`, `/admin/./`, `/admin%2f`, trailing
  `/admin/`, base-path stripping bugs behind proxies (WSTG-ATHZ-02).
- **Parameter tampering:** `?role=user` → `admin`, body `{"is_staff":true}`, hidden fields,
  mass assignment (03e BOPLA cross-link).
- **Static reachability:** find handlers *without* the authz decorator/middleware — list
  every route and tick which gateway it passes; missing middleware = confirmed.

## 4. Gateway & edge tests

- **Rate limiting** (API4/CWE-770): does it exist? bypass via `X-Forwarded-For` rotation,
  verb/host variation, alternate endpoints (login vs `/api/login` vs GraphQL) without limits.
- **CORS** (WSTG-CLNT-07): `Access-Control-Allow-Origin: *` with credentials, null-origin
  accepted, regex `*.evil.com` gap, preflight permissive.
- **Security headers** (WSTG-CONF-07/12/14): HSTS, CSP (no `unsafe-inline`/`unsafe-eval`),
  `X-Frame-Options`/frame-ancestors (clickjacking), `X-Content-Type-Options`, cookies flags.
- **CSRF** (CWE-352, MITRE #3): state-changing endpoints lacking token/`SameSite`,
  GET side effects, JSON endpoints accepting form-encoded cross-origin.
- **Proxy/WAF config in repo:** nginx `location` regex gaps, trailing-slash bypasses,
  `allow`/`deny` misorders, debug endpoints exposed (`/debug`, `/actuator`, `/server-status`).

## 5. Account/session lifecycle (WSTG-IDNT)

- Registration: username enumeration, open mass-user-creation, email verification bypass.
- Privilege changes must re-authenticate (step-up) — check password-change without current PW.
- Session logout/timeout verified by re-using old cookie after logout (WSTG-SESS-06/07).

## PoC discipline

Every proof = harmless marker or observable state difference on **localhost**; record the
two requests (yours → response excerpt) in REPORT.md; restore any account/role you changed
(`tags: auth-bypass`, `authz-bypass`, `account-takeover` → these are NO-GO blockers when confirmed).
