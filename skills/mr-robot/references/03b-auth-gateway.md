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
   differ for unknown-user vs wrong-password? (= enumeration, low-medium;
   when the check must happen cross-origin without contact, the oracle recipes
   are in [03o](03o-xs-leaks.md)).
4. **Password policy** (static): min length, complexity rules, breach-list checks in
   register/reset flows; `HaveIBeenPwned` k-anonymity usage.
5. **Reset flow** (WSTG-ATHN-09): token entropy, expiry, single-use, host-header-poisoned
   reset links, response discloses account existence.
   - **Host-header poisoning probe (bounded, ≤6 req):** trigger a reset for *your own*
     test account while overriding the host: `curl -s -D- -X POST
     http://localhost:PORT/forgot -d 'email=you@test' -H 'Host: mr-robot-poc.example'`
     (also try `X-Forwarded-Host`). If the emailed/queued link (read it from the
     local mailbox, queue, or log) embeds the *attacker-chosen* host instead of the
     canonical one, the reset flow is poisonable → the victim's token lands on a
     host the attacker controls = **account takeover** (`auth-bypass`, high). Only
     your own account's mail; marker host only; if the app ignores the override,
     record the canonical-host behavior as the passing control.

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
- **Security headers** (WSTG-CONF-07/12/14): HSTS, CSP (no `unsafe-inline`/`unsafe-eval` —
  presence alone isn't the finding: the bypass lanes — nonce reuse, strict-dynamic
  gadgets, JSONP/base-tag — live in [03a](03a-injection.md) "CSP bypass & payload
  delivery"; report-only downgrade counts), `X-Frame-Options`/frame-ancestors
  (clickjacking), `X-Content-Type-Options`, cookies flags.
- **CSRF** (CWE-352, MITRE #3): state-changing endpoints lacking token/`SameSite`,
  GET side effects, JSON endpoints accepting form-encoded cross-origin.
- **Proxy/WAF config in repo:** nginx `location` regex gaps, trailing-slash bypasses,
  `allow`/`deny` misorders, debug endpoints exposed (`/debug`, `/actuator`, `/server-status`).

## 5. Account/session lifecycle (WSTG-IDNT)

- Registration: username enumeration, open mass-user-creation, email verification bypass.
- Privilege changes must re-authenticate (step-up) — check password-change without current PW.
- Session logout/timeout verified by re-using old cookie after logout (WSTG-SESS-06/07).

### Session-replay / AiTM posture (stolen-token era — 2025/26's stolen-session shift)

Attackers moved from stealing passwords to stealing *tokens* (adversary-in-the-middle
phishing, malware reading the cookie jar): a bearer session bypasses MFA outright and
outlives the password reset that "fixed" the account. Verify each posture item on
localhost with ONE login + replay — never a credential-stuffing run:

- **Password-change ≠ session kill:** log in twice, change the password in one
  session, replay the *other* session's cookie → still 2xx = **stolen session
  survives the reset** (WSTG-SESS-08; high when combined with a token-theft path).
- **Revocation reachability:** after logout-all / "revoke sessions", replay both
  the access token (Authorization header) and refresh token → old ones still
  minted/accepted = logout theater (03k refresh-token replay).
- **Sender-constraining absent:** bearer JWT/opaque tokens accepted from *any*
  client with no DPoP `jkt` thumbpin or mTLS binding — record as posture finding
  (the absence is what makes any single stolen token replayable anywhere).
- **Step-up gaps:** sensitive flows (email change, payout, API-key create, MFA
  disable) trusting the bare cookie with no re-auth = one AiTM cookie → full
  takeover; `tags: account-takeover`.
- **Cookie hardening for the theft channel:** missing `HttpOnly` (XSS reads it),
  `Secure`, `SameSite=None` without CSRF story, non-`__Host-` prefix — each widens
  how *easily* the token can be stolen, not just used.

### Cookie tossing — sibling/parent-domain cookie injection (CWE-565)

A cookie set by *any* host under a registrable domain the org controls (or a
subdomain the attacker compromised — chain from 01 §7 dangling DNS) with
`Domain=.parent.example` is sent to **every** subdomain; the app then reads the
attacker's value where it expected its own.

- **Detect (source):** session/auth cookies set **without** the `__Host-` prefix
  (the prefix forbids `Domain=`, pinning the cookie to the exact host); apps that
  read a cookie by name with no provenance check; shared parent-domain SSO across
  unrelated apps (`login.`, `static.`, `dev.` under one `.example`).
- **Prove (bounded, localhost, own cookies only):** on `127.0.0.1:OTHER_PORT`
  (standing in for the sibling subdomain) set `session=mr-robot-poc-toss; Domain=localhost`
  — then show the target origin receives it and that the value *reaches* the app's
  session read (behavior flip, echo, or log line). ≤3 requests, one cookie, no
  other names — you are demonstrating precedence, not farming sessions. Clean up.
- **Impact:** session fixation across subdomains (`account-takeover` when the tossed
  value becomes the session), CSRF-token pre-seeding, logout-bypass. Fix:
  `__Host-` prefix everywhere + `SameSite` + never trust domain-wide cookies for
  auth ([06](06-remediation.md)).

### WebAuthn / passkeys — the 2025/26 factor (WSTG-ATHN-11/12 · CWE-345/287)

Passkeys are now the default second factor, and the ceremony has its own trust
bindings — checking "MFA: yes" in a report is no longer enough. Verify the
ceremony's *bindings* statically first; live checks only run against your own
registered credential on localhost.

- **Detect (source):** `navigator.credentials.get/create`, `webauthn` libs
  (`@simplewebauthn`, `webauthn-json`, Python `fido2`, Java `webauthn-server`),
  server verify calls — `verifyAuthenticationResponse`/`verifyRegistrationResponse`
  (simplewebauthn), `verify_get_response`, RP config (`rpId`, `origins`,
  `expectedOrigin`); recovery-code endpoints beside the passkey routes.
- **Verify (ceremony bindings — the four that matter):**
  1. **Origin/RP-ID pinning:** `expectedOrigin`/`origins` is an *allowlist*, not
     `window.location.origin` echo or `*`; `rpId` = the real registrable domain
     (an attacker page on a sibling subdomain must fail). Echo-or-wildcard = the
     ceremony accepts cross-site assertions = **bypass** (high).
  2. **User verification (UV):** `userVerification: "required"` on *authentication*
     — `"discouraged"`/missing lets a device-screen-lock-less assertion through;
     distinguish UV from UP (presence) in the stored `flags`.
  3. **Registration re-auth:** enrolling a new passkey demands an *existing* factor
     first (session + password/existing-passkey step-up) — a session-only enroll =
     one stolen session → persistent second factor (chain with the AiTM posture
     subsection above → `account-takeover`).
  4. **Recovery codes:** single-use (server-side consume), entropy ≥80 bits, no
     enumeration oracle on redeem, unused codes die when the user rotates; the
     classic shortcut (`?mfa=0` row in §2 applies here too).
- **Prove (own test account, localhost, ≤4 ceremony steps):** source evidence of a
  violated binding is the primary proof — paste the config/verify-call excerpt.
  The only live step: register + authenticate your *own* passkey against a locally
  started target and demonstrate the violated check (e.g. accepting an assertion
  while Origin comes from a forged-`Origin` request = the allowlist gap). No
  assertion forgery tooling, no COSE-key tampering — the config seam is the
  finding. `status: candidate` until the excerpt + one live step agree.
- **Impact:** origin/UV gap → cross-site assertion acceptance = full second-factor
  bypass (`auth-bypass`, NO-GO); enroll-without-step-up → persistent ATO;
  recovery weakness → same. Fix: strict allowlist + `required` UV + step-up on
  enroll ([06](06-remediation.md)).
- **MFA push fatigue (CWE-307):** push-based MFA with no rate limit/number-match
  — the attacker who has the password spams approve-prompts until the user taps.
  **Detect (source):** push provider config (Firebase Auth, Duo, Okta verify
  flow) with no attempt cap, no number-matching, no cooldown between sends.
  **Probe (bounded, own account, ≤3 pushes):** trigger at most three consecutive
  push attempts against *your own* registered device — three delivered without
  lockout/cooldown = the lane exists (medium-high; no third-party devices, ever).
  Fix: number-match + attempt cap + lockout + alerting (06).

## PoC discipline

Every proof = harmless marker or observable state difference on **localhost**; record the
two requests (yours → response excerpt) in REPORT.md; restore any account/role you changed
(`tags: auth-bypass`, `authz-bypass`, `account-takeover` → these are NO-GO blockers when confirmed).
