# 02 — Header & cookie reference (the §5/§6 checklist, expanded)

Consult this when writing the security-header checklist and cookie analysis.
It is the *why* behind every row `report.mjs` renders — presence alone is not
the test; the **value** decides.

## Response headers

| Header | Secure value | Notes / value traps |
|---|---|---|
| `Content-Security-Policy` | A policy that avoids `unsafe-inline` / `unsafe-eval` in `script-src` | `default-src 'none'` is max strictness (breaks apps); report nonce/hash-based script sources as good. `'unsafe-inline'` in script-src ≈ no XSS protection — present ≠ effective. Watch for `report-uri` (violation reports = logging surface). |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` (preloading needs `preload` + list entry) | Only meaningful over **https** (§5 marks n/a on http). `max-age` under ~6 months is weak; a bare-domain HSTS without `includeSubDomains` protects only that exact host. |
| `X-Frame-Options` | `DENY`, or `SAMEORIGIN` | Legacy twin of CSP `frame-ancestors`. If CSP has `frame-ancestors`, XFO is redundant-but-harmless. `ALLOWALL`/`*` = broken. |
| `X-Content-Type-Options` | `nosniff` | Without it, browsers may MIME-sniff responses (upload + JSON-as-script class issues). Value is binary: present-with-nosniff or missing. |
| `Referrer-Policy` | `no-referrer` (strictest) or `strict-origin-when-cross-origin` | Default in modern browsers is already `strict-origin-when-cross-origin` — an explicit *weaker* policy (`unsafe-url`) is the red flag, not absence per se. |
| `Permissions-Policy` | Feature list with `()` (deny) or minimal allowlist | Legacy name `Feature-Policy` (different syntax). `geolocation=()` style. |
| `Cross-Origin-Opener-Policy` | `same-origin` | Needed for `window.crossOriginIsolated` (SharedArrayBuffer) — if app uses those without COOP, note it. |
| `Cross-Origin-Resource-Policy` | `same-origin` (or `same-site` when CDNs must load assets) | `cross-origin` = anyone may embed/read; on cookie-less static assets that's often intentional. |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Only relevant together with COOP for isolation; many sites correctly omit — treat absence as informational unless isolation is expected. |
| `X-XSS-Protection` | `0` | Modern guidance: turn the legacy auditor **off** (`0`). `1; mode=block` is dated, `1` (unversioned) can be unsafe. Presence-with-`0` is correct; absence is fine too. |
| `Server` / `X-Powered-By` / `X-AspNet-Version` | absent | Version disclosure — informational, cheap to remove. |

### CORS headers (read as a set)

- `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true`
  → browsers **reject** this combo for credentialed reads (spec protection);
  a server reflecting an arbitrary Origin *with* credentials is the dangerous
  shape — check the actual `Origin` echo in capture.json.
- `Allow-Methods`/`Allow-Headers` too broad = larger preflight surface, not a
  vulnerability by itself.
- Missing ACAO on an API the SPA calls cross-origin = the call fails (bug),
  not a security hole.

### Caching (informational)

- Authenticated/API responses with `Cache-Control` absent or `public` may be
  stored by shared caches — note for sensitive bodies.
- `Vary: Cookie` on personalized responses: correct hygiene.

## Cookies — flag rules

| Flag / attribute | Rule |
|---|---|
| `HttpOnly` | **Must** on session/auth cookies — blocks JS read (XSS session theft). |
| `Secure` | **Must** on https sites — cookie only over TLS. Missing on https = observation (browser still stores it on https origins but sends per rules; on http targets `Secure` cookies are dropped by the browser entirely — so a http capture jar never holds them). |
| `SameSite` | `Lax` = default, safe for most; `Strict` = strongest (breaks cross-site entry links); `None` **requires** `Secure` (browsers reject `SameSite=None` without Secure). `None` without `Secure` in a jar = suspicious (shouldn't persist — if seen, note it). |
| `Domain` | Parent-domain scope (`Domain=example.com`) shares the cookie with every subdomain — broader than necessary; absent (`Host-only`) is tighter. |
| `Path` | `/` shares everywhere; narrow paths reduce exposure. |
| `Max-Age`/`Expires` | Session cookies (absent both) die on browser exit — good for sessions; absurd max-age on a session cookie = long-lived credential. |
| `__Host-` prefix | Requires Secure + Path=/ + no Domain — the hardened shape; absence isn't a flaw, presence of a *violating* prefix is (browser rejects such cookies). |
| `__Secure-` prefix | Requires Secure — same idea, weaker (Domain allowed). |

### Cookie diff reading

- **jar** (`§6 table`) = what the browser holds *now*.
- **Set-Cookie events** = history: who set what, with which flags, in order.
- **`document.cookie`** = the JS-visible subset (everything non-HttpOnly).
- jar ⊃ document.cookie — a session cookie absent from `document.cookie` but
  present in jar with `HttpOnly` = exactly as intended.

## Quick triage order when §5/§6 look bad

1. Session cookie without HttpOnly (immediate).
2. No CSP at all (defense-in-depth missing for an XSS-heavy world).
3. No HSTS on https.
4. `SameSite=None` without Secure / missing Secure on https.
5. Wildcard-or-reflected CORS with credentials.
6. Version disclosure (cosmetic).
