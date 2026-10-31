# 03g — Misconfiguration, crypto, logging & error handling (A02/A04/A09/A10:2025)

Mostly passive; items marked *(active)* are localhost-gated. Checkov/trivy already feed
findings.json — your job is the ones tools miss and the triage.

## Security misconfiguration — A02:2025 (#2, climbed from #5)

- **Debug & verbose modes:** `DEBUG=True` (Django/Flask), `debug: true` (Express),
  Spring actuator exposure, `pretty-print` stack traces to clients, dev servers bound in
  prod (`npm run dev` in Dockerfile), dev flags in env samples that prod inherits.
- **Default accounts/paths:** default admin panels, sample apps (`/examples`, `/docs`
  auto-swagger in prod), unchanged default secrets in shipped config.
- **CORS/proxy:** → 03b §4 (cross-link; don't duplicate).
- **Cloud/IaC:** public S3/GCS buckets, `0.0.0.0/0` SG rules, IAM `*` actions, unencrypted
  volumes, no MFA on root (checkov covers most — verify the *high* ones in source).
- **Containers:** privileged, `hostNetwork`, running as root (`USER` missing), secrets in
  `ENV`/layers, latest tags, no read-only rootfs (local rule `mr-robot-yaml-privileged-container`).
  - **Runtime sockets & identities (the escalation staples):** `docker.sock`
    mounted into any container/service (`/var/run/docker.sock:/var/run/docker.sock`,
    `volumes: - /var/run` in compose, socket-proxy services) = container→host root
    (`docker run -v /:/host` from inside); k8s service-account token auto-mounted
    at `/var/run/secrets/kubernetes.io/serviceaccount/token` with a role allowing
    `secrets`/`pods/exec`/`wildcard` verbs = cluster-grade escalation; hostPath
    mounts of `/`, `/etc`, SSH dirs; `automountServiceAccountToken: true` on
    workloads that need no API. Detect in compose/k8s manifests + Dockerfiles
    (checkov/trivy flag many — verify the *high* ones in source, same rule as
    the Cloud/IaC row above). Report as container-escape/secrets exposure
    (`rce-chain` when combined with a writeable host mount); 01 feeds the
    manifest inventory.
- **Secrets hygiene** (A07 cross): gitleaks hits — verify they're not *live* creds (rotate
  regardless); `.env` committed; keys in docs/fixtures.
- **HTTP server config in repo:** directory listing on, server/version headers leaking,
  outdated TLS min versions, missing `HSTS`, compression on sensitive responses (BREACH).

## Cryptographic failures — A04:2025

| Check | Pass condition | Fail → |
|---|---|---|
| Password hashing | bcrypt/scrypt/argon2id; per-user salt | md5/sha1/sha256-plain/PBKDF2<480k → **high** (03a detects) |
| Transport | HTTPS enforced, HSTS present, no `verify=False` | cleartext creds → high |
| JWT signing | HS256 secret ≥256-bit random / RS256 asym, alg pinned | weak/committed secret, `none` accepted → critical chain (03b) |
| Session cookies | `Secure; HttpOnly; SameSite` | any missing → medium |
| RNG for security | `secrets`/`crypto.random` for tokens | `random.`/`Math.random()` for reset tokens/API keys → high |
| TLS config | TLS1.2+ , modern ciphers, no cert verify off | legacy ciphers/verify off → medium |
| Encryption at rest | app-layer encryption for PII/PCI where promised | plaintext sensitive fields → high |
| Padding/oracles | AEAD or padding checks with constant-time compare | CBC-oracle patterns / `==` on HMACs (timing) → medium (WSTG-CRYP-02) |
| Key management | keys from env/secret manager, not source | hardcoded keys → critical (gitleaks/local rule) |

## Logging & alerting — A09:2025 *(static + one active check)*

- Logged: failed logins (with IP/UA), authz denials, privilege changes, admin actions,
  validation failures, input with control chars.
- **Not** logged: passwords/tokens/keys/PII in full (log redaction present?).
- Alerting exists for auth-failure bursts (a rule/webhook/SIEM config in repo?) —
  **logged without alerting = medium finding** ("visible only if someone looks").
- Active (gated): trigger failed login + 403 locally → confirm both hit the log.

## Mishandling of exceptional conditions — A10:2025 (new!)

The new Top-10 entry — check for **fail-open** and swallowed errors:

- Auth/permission code paths wrapped in broad `try/except: pass` → request proceeds
  unauthenticated on error (`except Exception: continue` around token verify = **critical**).
- Fail-closed expected but fail-open present: rate limiter errors → unlimited access;
  signature verification exception → `return True`; feature-flag service down → unrestricted.
- Generic error handler hides real failures but returns 200 (monitoring blind spot) vs
  proper 5xx + A09 logging.
- Logic errors under abnormal conditions: negative/overflow inputs reaching unchecked
  math (ties to 03e races and 03h overflows), null handling that skips validation.
- Grep patterns: `except.*:\s*pass`, `catch\s*\{\s*\}`, `ignore_errors`, `|| true` in
  security-relevant paths, `on('error')` that swallows, `finally` returning success.

## Resource exhaustion / DoS — CWE-770 (MITRE #25)

- Unbounded: request body size, query pagination (`?limit=999999999`), zip/image
  decompression without limits (zip-bomb → local), regex backtracking on user input
  (ReDoS — test one pattern with a long payload locally), N+1 queries, missing timeouts
  on outbound calls, unbounded file reads. *(active: one bounded probe each, ≤5 rps)*

## Output

Fold confirmed items into findings.json with proper A0x + CWE tags; config/crypto items
almost always come with a concrete file:line fix (config key + correct value) in the
report's remediation column.
