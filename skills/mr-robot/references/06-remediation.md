# 06 — Remediation playbook

Fix patterns that actually close findings. Load this in Phase 7, after the verdict —
one section per finding family, each tied back to its attack catalog (`03a`–`03p`).
Scanner-provided remediation text (`remediation` fields from kube-linter/nuclei/trivy)
is the source of truth when present; this file is the pattern behind it.

## Rules of remediation

1. **Smallest effective fix.** Fix the root cause at the sink, not the symptom at the
   report. No drive-by refactors.
2. **Evidence closes findings, not patches.** Every fix goes through
   `scripts/retest.sh <baseline>/findings.json [target] [--live url]` — a finding is
   closed only when the retest says `fixed` with its tool having run.
3. **`unknown` means unfinished.** If the tool didn't run in the retest, either fix
   the coverage gap or justify manually in the report — never silently credit it.
4. **Never suppress to pass.** Not in the scanner config, not by severity edits in
   `findings.json`, not by deleting the test. Accepted risk is recorded in REPORT §7
   with the accepter's name, or it isn't accepted.
5. Apply code changes only with the user's explicit approval, and only inside the
   files the fix requires (Phase 0 RoE applies to writes, not just tests).

## What does *not* count as a fix

- Disabling/ignoring the rule (`# nosec`, `// nosemgrep`, `.trivyignore`) with no
  compensating control
- Input denylists / blocklists for injection ("forbid `DROP TABLE`") — use binding
- String-concat "escaping" (quote-swapping in SQL, manual HTML entities)
- Hiding the endpoint (renaming, obscurity) instead of authorizing it
- Moving the vulnerable code to another file (retest will call it `new`)
- "We rate-limit it now" in place of an authz/IDOR fix

---

## Injection (03a)

- **SQL/NoSQL:** parameterized queries / prepared statements everywhere, including
  "internal" string building; ORM raw SQL → bound parameters; identifiers
  (table/order/column names) → strict allowlist, never parameters-by-concatenation.
- **Command/argument injection:** never `shell=True`/`os.system`/backticks with
  user data; pass argv arrays; if a shell is unavoidable, allowlist the full command
  pattern. File paths → reject separators, resolve then prefix-check.
- **SSTI/template:** disable expression evaluation in user-reachable templates
  (Jinja `SandboxedEnvironment`, no `render_template_string` on untrusted input);
  keep autoescaping on for HTML contexts.
- **XSS:** contextual output encoding via the framework; `innerHTML` → `textContent`;
  strict CSP without `unsafe-inline`.
- **XXE:** disable DTDs/external entities in every XML parser (libxml
  `no_network`+no DTD, Java `FEATURE_SECURE_PROCESSING`, `defusedxml` in Python).

## Auth, sessions, JWT (03b)

- **JWT:** pin accepted algorithms server-side (`HS256`/`RS256` explicit — never
  `alg: none`, never header-driven key selection); verify `exp/aud/iss/nbf`; rotate
  any key a confusion attack could reach; `kid` → never a filesystem/URL path.
- **Sessions:** `Secure; HttpOnly; SameSite=Lax|Strict`; server-side invalidation on
  logout/password change; regenerate id on privilege change; absolute + idle timeouts.
- **Login:** argon2id/bcrypt with proper cost; identical errors for unknown user vs
  bad password; rate limit per-account *and* per-IP; lockout with backoff.
- **Password reset:** single-use, short-TTL, unguessable tokens; no user-enumeration
  in responses; invalidate on use.

## Access control / BOLA (03b)

- Server-side authorization on **every** object fetch: load the object *scoped to the
  caller* (`where id=? and owner=current_user`) — never fetch-then-check-in-app.
- Deny by default: routes/roles outside the allowlist → 403, including for "internal"
  endpoints (admin UIs, debug routes).
- IDOR hardening is the check, not the ID format: sequential IDs are fine only with
  per-object authz.

## SSRF / URL fetching (03c)

- Allowlist destination hosts/schemes; if fetching by URL is the feature, resolve DNS
  first, then block private/link-local/metadata ranges **on the resolved IP**
  (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `169.254/16`, `::1`, metadata
  `169.254.169.254`) — re-check after every redirect, never forward `Authorization`.
- Egress through a proxy that enforces the same policy (defense in depth); disable
  URL schemes like `file://`, `gopher://`, `dict://`.

## File upload / path traversal (03c)

- Resolve (`realpath`) + verify the final path stays under the intended base dir;
  allowlist extensions; random server-generated names; store outside the webroot;
  serve with `Content-Type` + `Content-Disposition: attachment` + sandbox (separate
  origin). Parse archives with path-escape checks (zip-slip).

## Secrets & supply chain (03d)

- **Rotate first, then remove** — treat any committed credential as compromised:
  revoke/rotate, then delete from code, then purge history (`git filter-repo`) and
  re-clone mirrors.
- Move to env/secret manager; `gitleaks` pre-commit + CI gate so it cannot return.
- Dependencies: exact pins + lockfiles, `osv-scanner`/`trivy sbom` in CI, verify
  signatures/checksums for anything downloaded at build time (cosign/sigstore for
  images), one dependency manager per project — no `curl | sh` installs.
- **Backdoors/implants:** remove the implant *and* audit blast radius — what it read
  or exfiltrated, what it could reach, every credential in its process env (rotate),
  its persistence mechanisms (cron, launchd, git hooks, CI), plus the history it
  lived in. Removing the file is not removal.

## Misconfiguration (03g) — app, containers, IaC

- **HTTP security headers:** HSTS (after confirming HTTPS-only), CSP with
  `frame-ancestors`/`X-Frame-Options` equivalent, `X-Content-Type-Options: nosniff`,
  no verbose `Server`/`X-Powered-By`; TLS ≥ 1.2, modern cipher suites, cert rotation.
- **Errors/logging:** generic client errors (no stack traces/SQL in responses);
  security events logged (authn failures, access denials) *without* secrets/PII/tokens.
- **Dockerfile:** pin base image by digest, non-root `USER`, no secrets in
  `ARG`/`ENV`/layers, multi-stage so build tools don't ship, drop packages.
- **Kubernetes:** `runAsNonRoot`, `readOnlyRootFilesystem`, `seccompProfile:
  RuntimeDefault`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`,
  resource requests/limits, pinned image tags, no default-namespace workloads,
  NetworkPolicies default-deny.

## Races / TOCTOU / business logic (03e)

- Serialize the check-and-use: DB transaction with `SELECT … FOR UPDATE`, optimistic
  version column, or atomic compare-and-set (`update … where balance >= ?`).
- Money/inventory flows: idempotency keys on mutations, single-use tokens for
  voucher/redemption paths, constraints at the DB layer (unique indexes) — not
  application-level checks alone.
- Quotas/limits: enforce server-side atomically; client-side counters are UI only.

## Rate limiting / DoS (03g/03i)

- Token bucket per user *and* per IP at the edge; body/depth caps: request size
  limits, JSON nesting depth, GraphQL query depth/complexity limits, batch-size cap,
  header-count caps. Timeouts on all outbound calls.

## GraphQL & WebSocket (03j)

- Authorization **per resolver/field** with deny-by-default (object loaded scoped to
  caller — BOLA applies through nesting); introspection off (or authed) in prod;
  persisted-query allowlist; complexity/depth/batch limits.
- WS: authenticate during the upgrade handshake *and* per subscription start; validate
  `Origin`; don't reuse session cookies cross-site (CSWSH); server-authorize every
  event delivered.

## OAuth / OIDC (03k)

- `redirect_uri`: exact-match allowlist (no prefix/suffix matching, no open
  subdomains); `state` generated server-side, single-use, verified; PKCE required
  for public clients; reject code/token substitution (`nonce`, `aud`, `iss`, one-time
  code).
- Link-account flows bind identity **server-side at the provider** — never trust an
  email/name claim from the client round-trip.

## HTTP protocol edge (03i)

- One canonical `Host` decided at the edge; reject/park unknown hosts; strip or
  normalize duplicate `Host`/`Content-Length`/`Transfer-Encoding` before the app
  (single parsing authority — the smuggling fix is *one* parser, not two).
- Cache key includes `Host` + auth state + the vary set; never cache personalized or
  401/403 responses; sanitize CR/LF in any header value you reflect.

## LLM / agent surfaces (03f)

- Treat all retrieved/user content as untrusted data: separate instructions from
  content, never let model output authorize a tool call without deterministic
  policy checks; least-privilege tools; egress/allowlist controls on agent-driven
  fetches; sandbox code execution; audit-log every tool invocation.

---

## Closing a fix (the loop)

```bash
# after fixes are approved + applied:
bash skills/mr-robot/scripts/retest.sh <baseline-run>/findings.json [target] [--live http://localhost:PORT]
# → retest.json: fixed / persisting / unknown / new  (exit 0 = clean)
# mark fixed findings status:"fixed" in findings.json → re-run score.mjs → update REPORT §7
```

Persisting → fix again (the reason line says whether severity moved). `new` → triage
as a fresh finding. `unknown` → get the tool running (install/coverage) and re-run;
that is the whole point of the classification.
