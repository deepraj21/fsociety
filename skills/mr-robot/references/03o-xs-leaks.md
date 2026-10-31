# 03o — Cross-origin leaks (XS-Leaks): side-channel oracles (CWE-200/208/209 · WSTG-ATHZ-01 · A01:2025)

No XSS, no injection, no smuggled request — the attacker's page just *observes how
the victim's browser behaves* while talking to the target origin, and infers
sensitive state bit by bit: does this account exist, did the password reset email
arrive, what's in this search result, which hostname did that redirect go to.
PortSwigger's Top 10 of 2025 put **two** XS-Leaks in the final ten and their
panel's headline for 2026 was "the rise of side-channels as a core exploitation
primitive" — this file is that trend, operationalized.

**Active-phase file:** localhost target + user confirmation + bounded probes.
Cross-origin experiments need a *second* local origin (different port = different
origin) — run the attacker page from `127.0.0.1:OTHER_PORT`, never from a domain
you don't own. All bounds below are hard.

## The oracle families (Detect → Verify → Prove)

### 1. Response length / ETag oracles (Top-10 #6 — Cross-Site ETag Length Leak)

A response's `ETag` is (usually) a hash of its bytes: **same bytes ⇒ same ETag,
across origins**. The attacker primes their own cache with the victim URL, then
compares ETags — an equality check on *response content they can't read*.

- **Detect (source):** sensitive endpoints returning `ETag`/`Last-Modified`
  (framework default: many Rails/Django/Express setups emit them on everything);
  responses whose length varies with content (search results, "wrong password"
  vs "user not found", quota pages).
- **Verify:** `curl -sI 'http://localhost:PORT/search?q=mr-robot-probe' | grep -i etag`
  — an ETag on a state-varying response is the raw material. Does it change
  between two states you control (logged-in vs logged-out)?
- **Prove (bounded, local two-origin):** attacker page at `127.0.0.1:OTHER`
  fetches the victim URL in a hidden iframe/fetch (no-cors), reads *its own*
  ETag for the same URL from its own cache, and compares — a match/no-match
  answers "is the victim's content at this URL identical to my known state?"
  Recipe: prime → compare → report the oracle as a boolean channel. ≤10 requests,
  marker query values only.
- **Impact:** account/search-state enumeration at scale; pair with 03b
  (what the states *are*) for severity.

### 2. Connection-pool / redirect oracles (Top-10 #8 — XSS-Leak)

Chrome prioritizes connections: a request queued behind an in-flight one to the
*same origin* behaves differently from one to a fresh origin. Observing **when**
your request completes leaks *where* the victim's browser was redirected —
hostname extraction without reading a single byte.

- **Detect:** any redirect that carries state (password-reset → `?token=`,
  OAuth authorize → IdP, `/out?url=` jumps); the *target hostname* is the secret.
- **Verify:** does the redirect land cross-origin (timing differs) or same-origin?
  `curl -sI` the flow and map the chain first.
- **Prove (localhost only):** attacker page times a `fetch()` to a resource that
  triggers the redirect while the victim session is active, against a control
  timing baseline (same request, no session). A reproducible delta = the oracle.
  ≤20 timed requests (10 + 10 control), single run — never a sustained hammering;
  record the distributions in the report, and say plainly that timing findings
  are statistical (`status: candidate` until the delta reproduces twice).
- **Impact:** leak of reset tokens' destination, IdP hostnames, internal route
  names — feeds 03k (OAuth) and 03b (reset flows).

### 3. Frame/window-count & load-state oracles (the classics)

- **Detect:** pages that conditionally embed frames (ad/iframe loaders, PDF
  viewers, nested dashboards), endpoints whose *existence* is the secret
  (`/admin` 403 vs 404 renders differently — cross-origin you can't read status,
  but you CAN read whether an iframe fired `load` vs `error`).
- **Prove:** attacker page embeds the URL and inspects `iframe.onload` /
  `iframe.onerror` / `iframe.contentWindow.length` (frame count is
  cross-origin-readable). Login-state oracle: same URL with/without the victim
  cookie → different frame behavior = "logged in?" bit. ≤5 embeds per oracle,
  one bit each, marker values only.
- **Impact:** account-existence and session-state bits → targeted CSRF/credential
  attempts instead of blind spraying (03b/03e).

### 4. Cache-probe (XS-Search via cache)

Prime the victim's cache with a URL only *they* can cause to be fetched; later,
time a fetch of the same URL — a cache hit means the victim (or their session)
touched it. Closely related to cache poisoning/deception in
[03i](03i-http-protocol.md) but the *observation* is cross-origin timing.

- **Detect:** cacheable sensitive URLs (search pages with `public`/`s-maxage`
  mis-set, CDN caching personalized responses).
- **Prove (bounded):** 5 probe timings against 5 control timings, localhost CDN
  or app cache only, then **purge and verify the purge** (03i discipline applies).
- **Impact:** activity tracking ("did the admin open this ticket?") — medium
  standing alone, high when it answers a security-relevant question.

### 5. Timing oracles (statistics, not vibes)

- **Detect:** endpoints whose response time correlates with secret state
  (DB lookups on exists-checks, string compare on tokens, blocking rate-limits).
- **Verify:** interleave target + control requests (never sequential blocks —
  network jitter biases runs), ≥10 samples each, compare medians. A delta under
  ~20ms on loopback is noise; say so.
- **Prove:** report the distributions verbatim. Timing alone is `candidate`;
  a consistent, mechanism-explained delta (source shows a secret-dependent
  query) upgrades it. Cross-link [03g](03g-config-crypto-misc.md) timing/oracle
  row and 03h's constant-time rules.

## Source-side detection (Phase 1 — what makes an app leak-prone)

- State-varying responses with stable lengths/ETags (existence oracles).
- Redirects carrying secrets in the *target URL* rather than in a server-side
  session (03b reset flows, 03k OAuth).
- Personalized responses with `Cache-Control: public` / missing `no-store`.
- Error pages that differ per state (403 vs 404, message length) — the raw bit.
- No `Cross-Origin-Opener-Policy`/`Cross-Origin-Resource-Policy` on sensitive
  responses; `frame-ancestors` absent (also 03b clickjacking row).

## Defenses to check (and to recommend in 06)

| Defense | Defeats |
|---|---|
| `Cache-Control: no-store` on state-varying responses | cache-probe, ETag compare |
| Uniform 404/403 + constant-size bodies/errors | existence & length oracles |
| `Cross-Origin-Opener-Policy: same-origin` (+ COEP/CORP) | window/pool oracles |
| Timing: constant-time compares + artificial floor on auth paths | timing oracles |
| `frame-ancestors 'none'` + `Referrer-Policy` | frame-count leaks, referrer leakage |

## Probe discipline (Phase 0 — hard bounds)

| Bound | Value |
|---|---|
| Requests per oracle | ≤20 (timed) / ≤10 (prime+compare) / ≤5 (frame embeds) |
| Timing runs | one run of ≥10 interleaved samples per condition; no loops of loops |
| Origins | loopback only — attacker page and target both on 127.0.0.1, different ports |
| Payloads | marker values (`mr-robot-poc`), no token harvesting beyond the oracle bit |
| Artifacts | record request timings/frame events verbatim in REPORT.md |

Exit/verification: this is a recipe file — the agent runs the bounded probes by
hand from this file (or via [03l](03l-traffic-interception.md) HAR when a capture
already shows the redirect chain). Every oracle result is `status: candidate`
until reproduced twice with the mechanism explained from source.

## Chaining ideas (the actual exploit path)

Length/error oracle → account enumeration (03b) → targeted credential testing ·
redirect-host leak → OAuth/IdP confusion (03k) or internal hostname disclosure
(03c) · cache-probe → admin activity mapping → timing CSRF against the exact
moment (03e races) · login-state bit → one-shot CSRF on state-changing POST
(03b) — side channels are the *recon* half of an otherwise unexploitable chain;
report the chain, not just the bit.

## References

- PortSwigger Top 10 of 2025: Cross-Site ETag Length Leak (arkark) · XSS-Leak
  cross-origin redirect leak (babelo) · panel trend note "side-channels as a
  core exploitation primitive"
- PortSwigger Web Security Academy — XS-Leaks chapter (oracle patterns + defenses)
- `Cross-Origin-Opener-Policy` / `Cross-Origin-Resource-Policy` / `CORB` specs
- Related: [03i](03i-http-protocol.md) cache · [03b](03b-auth-gateway.md) state
  oracles · [03k](03k-oauth-oidc.md) redirect chains · [03l](03l-traffic-interception.md) HAR
