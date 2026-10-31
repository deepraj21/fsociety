# 03i — HTTP protocol attacks (CWE-444/644/113/1333 · WSTG-ATHO/INJT-03/04)

Attacks on the *wire format* itself — between client, proxy, and app. Most only
matter when a proxy/CDN/reverse-proxy sits in front (check the repo for nginx,
traefik, caddy, envoy, cloudfront config in Phase 1 — if present, this file is live).
**Active-phase file:** localhost target + user confirmation + bounded probes only.

## HTTP request smuggling / desync — CWE-444 (WSTG-ATHO-06)

Front-end and back-end disagree on where one request ends: CL vs TE parsing,
0-content-length, chunked extensions. One request becomes two — poison a queue,
bypass front-door auth, leak another user's response.

- **Detect (static):** proxy config with request rewriting, `Content-Length` +
  `Transfer-Encoding` both honored, HTTP/1.1 kept alive to upstream, HTTP/2→HTTP/1.1
  downgrade gateways (cloud LBs, envoy) — H2.CL / H2.TE / H2.TE.CL are the modern
  variants and the most likely against a local dev stack.
- **Verify:** only a proxy *in the path* makes this real; an app directly serving
  requests cannot be desynced by itself. Confirm the topology before spending probes.
- **Probe (bounded, local, ≤13 requests total):**
  ```
  # CL.TE probe — front-end uses CL, back-end uses TE. The "0\r\n\r\n" ends the
  # chunked body early for the back-end; anything after starts a new back-end request.
  printf 'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX' | nc -q 1 localhost PORT
  # TE.CL probe — inverted: back-end reads CL=6, front-end reads TE until 0-chunk.
  # Smuggle a marker request and watch for a 404/response to a request you never sent:
  printf 'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG' | nc -q 1 localhost PORT
  ```
  Prefer the automated runner over hand-rolled probes: `scripts/desync-probe.sh <url>`
  sends the CL.TE/TE.CL/CL.0 families (plain, hidden-tab, doubled, x-prefix, raw
  body) with marker GET bodies and compares response counts *and* status sequences
  against the target's own pipelined baseline — exit 1 = unsolicited/shifted
  responses (candidate desync), exit 0 = uniform (expected for direct-only
  topology). See [03l](03l-traffic-interception.md)
  for the interception side (topology confirmation via a local proxy).
- **Time oracle:** smuggle `GET /slow-path HTTP/1.1` (any route that takes >2s, e.g.
  a sleep/health endpoint) in the prefix; if the *next* connection's response is
  delayed ~that long, the back-end queued your smuggled request → confirmed desync.
- **Prove:** smuggle a harmless request (`GET /mr-robot-poc HTTP/1.1`) and show the
  *following* request on a fresh connection receives its 404/response — you controlled
  another connection's response. That is the whole impact; never smuggle state-changing
  or cross-user requests.
- **Impact:** front-door auth bypass (smuggled request skips the authenticating
  proxy), queue poisoning, cache poisoning (below). Chain tags: `auth-bypass` when the
  proxy is the only gate. NO-GO-class when confirmed with a proxy in path.

## Modern desync families — CL.0, h2c downgrade, 103 splitting, browser-origin (CWE-444)

The 2024–26 staples the classic CL.TE/TE.CL probes never touch. Same discipline as
above: topology first, marker-grade payloads only, candidate until the access log
agrees.

- **CL.0 (zero-content-length):** a hop honors `Content-Length` but *parses no body*
  for that request — the body bytes become its next request on the connection.
  - **Detect:** backend/framework that ignores request bodies on GET (Python
    `http.server` does — the dev-proxy class), proxy rules that buffer POSTs but
    pass GETs through raw, `Content-Length` present + no `Transfer-Encoding`.
  - **Probe:** `scripts/desync-probe.sh` family 5 (raw marker GET as a
    `Content-Length` body, no TE). A *direct* backend that ignores GET bodies flags
    here — that is the CL.0 necessary condition, reported as candidate: any
    queueing proxy in front turns it into cross-user response hijack.
  - **Prove:** smuggling §Prove — the marker arrives as its own request on a later
    connection's response (grep the access log).
- **h2c / prior-knowledge downgrade:** a client speaks h2c upgrade or HTTP/2
  prior-knowledge (`PRI * HTTP/2.0`) to a front-end that speaks HTTP/2 inbound and
  HTTP/1.1 upstream — the H2.CL/H2.TE reinterpretation from the section above,
  *on purpose* at the downgrade hop.
  - **Probe (bounded, 2 requests):**
    ```
    curl -s -o /dev/null -w '%{http_version}\n' --http2-prior-knowledge http://localhost:PORT/
    curl -s -o /dev/null -w '%{http_version}\n' http://localhost:PORT/   # baseline
    # different routing/status between the two = two parsers active → H2.* variants live
    ```
    then the H2.CL/H2.TE nuclei templates against localhost only.
- **HTTP/2 CONNECT tunneling (Top-10 #9):** a front-end that speaks H2 inbound
  *and* honors `CONNECT` over it (proxies, API gateways — support is spreading)
  hands out raw tunnels to whatever `Host:port` the client names — the ancient
  HTTP/1.1 verb rediscovered on the H2 listener, with internal port-reach as the
  payoff.
  - **Probe (bounded, ≤3 requests):** capability first —
    ```bash
    curl -s -o /dev/null -w '%{http_code}\n' --http2-prior-knowledge \
      -X CONNECT -H 'Host: 127.0.0.1:8080' http://localhost:PORT/
    ```
    anything but `405`/`501` = CONNECT is parsed → candidate. If repo config shows
    a proxy/gateway with HTTP/2 (envoy `connect_config`, nginx/haproxy H2), one
    follow-up: tunnel to ONE loopback port where you run `nc -l` — a banner
    arriving through the tunnel proves internal reach. ≤3 tunnel targets, banner
    bytes only, no sustained stream.
  - **Report:** candidate until an actual internal service answers through it;
    chain tags `ssrf` (edge-adjacent reach) + recon — see [03c](03c-ssrf-access-file.md)
    for what internal reach buys.
- **103 Early Hints response splitting:** a proxy that *forwards* interim `103`
  responses + an app that reflects input into `Link` headers = split a response
  across users without touching `200`.
  - **Probe (bounded, ≤4 requests):** capability first — does any `HTTP/1.1 103`
    appear at all (`printf 'GET / HTTP/1.1\r\nHost: x\r\n\r\n' | nc -w 3 localhost PORT`
    + grep `103`)? Then reflection: `curl -D- 'http://localhost:PORT/?x=mr-robot-poc'`
    and check `Link:` carries the raw marker. Marker value only; a 103 with
    attacker `Link` = candidate (`CWE-113`, chain with cache poisoning below).
- **Browser-origin desync (no proxy required):** the browser reuses a keep-alive
  connection to the app's origin; a poison prefix parked on that connection serves
  the *next* request's response to the wrong party — client-side desync.
  - **Detect:** keep-alive to origin + any reflection point + pages worth serving
    to a wrong victim (error/login bodies).
  - **Prove (localhost-only):** poison a loopback connection with a marker request,
    then a second `fetch()` from a same-origin page must receive the marker's
    response instead of its own. Never run this against origins you don't own
    (it hijacks *other users'* requests by design).

## Parser differentials — interpretation becomes the vulnerability (CWE-444/178)

Two components read the *same bytes* differently and the security decision is made
by whichever one loses the argument (Top-10 #10, joernchen's language/framework
case studies). Smuggling above is the HTTP instance — the class is far wider, and
it only takes a hop: any place where ≥2 parsers touch input is a candidate.

- **Detect (Phase 1):** named pairs in the repo's config/code — nginx `merge_slashes`/
  `decode_escapes` vs app router, CDN path normalization vs origin, WAF regex vs
  framework decode order, `URL()` (WHATWG) in JS vs `urllib.parse`/`net/url` server-side,
  JSON libs that disagree on duplicate keys or number precision.
- **Classic pairs to probe (≤5 requests each, marker payloads only):**
  - **Path:** `/%2e%2e/`, `//admin`, `/./x`, `..;/`, backslash `..\`, trailing `.`/`%20`
    — front-end says `/safe/read`, backend resolves elsewhere (cross-link 03c).
  - **Identity/host:** punycode vs displayed hostname in redirects & rendered links —
    [03o](03o-xs-leaks.md) §2 is the *leak* half, here it's the spoof half (03k too).
  - **Param/JSON:** duplicate keys (`{"id":1,"id":2}` — validator reads first, app
    reads last), `id=1` vs `id[]`, content-type sniffing (`text/json` vs `application/json`
    accept/deny), charset layers (`UTF-7`, BOM) shifting parse boundaries.
  - **Multipart:** boundary quirks (missing/duplicate boundary, `boundary=` in
    param vs header), `filename` vs `name` field confusion (`name="avatar";
    filename="../../x"` — one parser keys the field, the other the filename;
    also `filename*=` RFC 5987 vs plain `filename`), part-header smuggling past
    WAFs that don't reassemble. ≤5 requests; cross-links [03c](03c-ssrf-access-file.md)
    upload lane and [03p](03p-grpc-sse.md) JSON↔proto transcoding.
  - **XML vs HTML:** namespace/entity handling disagreement feeding XXE (03a) —
    one parser resolves entities the other ignores.
  - **HTTP layer:** CL/TE/Host — already covered by the smuggling sections above.
- **Prove:** capture *both readings of one request*: the app's log line or response
  (what it did) vs the front-end's (what it admitted) — verbatim excerpts in the
  report. The disagreement itself is the candidate; severity comes from the worst
  downstream interpretation (traversal, authz skip, cache key mismatch → 03i cache).
- **Impact:** filter bypass → XSS/LFI, routing bypass → unprotected routes, the
  desync class when the parsers disagree on *framing*; always chain to the concrete
  sink rather than reporting "differential" alone.

## Web cache poisoning / deception — WSTG-ATHO-11 (CWE-349)

Unkeyed input (headers the cache ignores when hashing) poisons a response other
users then receive; deception makes a victim's cache store *your* response.
Observing *whether* the victim's browser touched a cached URL is the cross-origin
side of the same coin — cache-probe XS-search lives in [03o](03o-xs-leaks.md).

- **Detect:** any cache in path (CDN, nginx `proxy_cache`, Varnish, Next.js
  `unstable_cache`, Redis/response caches in app code keyed on URL only).
- **Verify:** which request parts form the cache key? If `X-Forwarded-Host`,
  `X-Forwarded-Scheme`, `Origin`, `Accept`, or path-normalization oddities
  (`/x..%2f`, `/x%3f`, `//`) influence the response body/headers but are NOT in the
  key → poisonable.
- **Prove (bounded):**
  ```
  curl -s -D- -H 'X-Forwarded-Host: mr-robot-poc.localhost' http://localhost:PORT/ | grep -i 'mr-robot-poc'
  # echoed into a Link/canonical/asset URL = reflected; then check a second,
  # unauthenticated request WITHOUT the header — if the poison persists → confirmed.
  ```
  Keep the poison value the marker hostname; purge/restart the cache afterwards and
  **verify the purge** (cleanup is part of the PoC).
- **Deception variant:** `X-Original-URL` / `X-Rewrite-URL` accepted by the cache but
  ignored by the app → cache stores a 200 for a URL the app never serves.
- **Internal/framework caches (Top-10 #6 — "the stale elixir"):** not every cache
  is an edge — Next.js ISR/`revalidate`/`unstable_cache`, Rails page/action caching,
  Django cache middleware, and app-level response memoization persist poisoned
  bodies *inside the origin*, often keyed looser than the app's own routing.
  Poisoning here survives an edge purge and needs no proxy in the path.
  - **Detect:** `revalidate`/`unstable_cache`/`generateStaticParams` + ISR docs,
    framework cache decorators, response memoization keyed on URL; `Cache-Control`
    emitted by app code rather than the edge; stale-while-revalidate windows.
  - **Prove (bounded, localhost):** poison via one unkeyed input → attempt the edge
    purge (or wait out max-age) → a fresh cookieless request STILL serves the
    poisoned body = internal-cache finding. Clearing it with a rebuild/restart is
    the remediation proof — record both. ≤10 requests + 1 purge attempt + 1
    verification, marker payload only, state restored after.
  - **Chains (why this ranked #6):** internal cache + routing/serialization quirks
    compose into full-page-takeover chains in framework repos — when the stack is
    Next.js (or Rails/Django with page caching), pair any staleness finding with
    [03n](03n-known-cves.md) known cache-key/routing CVEs and keep
    `status: candidate` until the stale body reproduces twice.

## Host-header attacks — CWE-644 (WSTG-ATHN-09, INJT-03)

- **Detect:** `request.host` / `Host:` read directly into URLs, links, password-reset
  emails, cache keys, password-reset routing (`/reset?token=` links built from Host).
- **Verify:** does the app trust Host without an allowlist? Does the *proxy* normalize
  it first (nginx `server_name` catch-all `_`, traefik HostRegexp gaps)?
- **Prove:**
  ```
  curl -s -D- -H 'Host: mr-robot-poc.localhost' http://127.0.0.1:PORT/reset -X POST -d 'email=test@test'
  # poisoned link in response/log = medium; if the proxy ROUTES on Host
  # (Host: internal-admin → different vhost) = high auth-bypass path
  ```
  Password-reset poisoning (link points at attacker domain, token intact) chains to
  account takeover (03k/03b) → `tags: account-takeover`.

## CRLF / header injection / response splitting — CWE-113 (WSTG-INJT-04/16)

- **Detect:** user input into response headers (`redirect(`, `set_header(`,
  `Location: $INPUT`, `Set-Cookie: $INPUT`) without `\r\n` stripping; input echoed
  raw into HTML stream without chunking.
- **Prove:** `%0d%0aSet-Cookie:%20mr-robot-poc=1` in a reflected param or redirect
  target → look for the injected header in `curl -D-`; `%0d%0a%0d%0a<script>` for
  classic splitting. Inject only the marker cookie/header — never session fixation
  with a real value.
- **Chain:** injected header + cache = stored XSS/poisoning (above); injected
  `Location` = open redirect (03c).

## ReDoS — CWE-1333 (A05:2025)

Catastrophic backtracking regexes on attacker input hang a worker — a *bounded*
single-shot DoS proof, never a flood.

- **Detect:** nested quantifiers / alternation-overlap in repo regexes:
  `(a+)+`, `(a|a)*`, `(.*a){n}`, `\s*\S*\s*`, user-facing validation regexes
  (`grep -rnE '\(\.\*\)|\(\.\+\)\)|\(\[^\]]*\]\*\)\+'`), email/URL validators,
  WAF rules in repo, Re2 vs backtracking engine (`re` vs `re2`/`RE2`).
- **Verify:** is the regex applied to *attacker-length* input (body, header, URL,
  upload filename)? Length caps / timeouts in front?
- **Prove (time-boxed, ≤5s):** send one crafted string sized to the pattern (e.g.
  `'a' * 30 + '!'` against `(a+)+$`) and time the response:
  ```
  curl -s -o /dev/null -w '%{time_total}\n' -X POST http://localhost:PORT/validate \
       -H 'Content-Type: application/json' -d "{\"s\":\"$(printf 'a%.0s' {1..30})!\"}"
  # linear-time → ms; exponential → seconds and growing with each added 'a'.
  # Confirm growth (30→35 chars), then STOP — one growing sample is the proof.
  ```
  A hanging request: kill the curl, do not retry. Report as medium (worker exhaustion),
  high if unauthenticated internet-facing surface exists in the deployment story.

## HTTP/2 denial of service — continuation flood & rapid reset (CWE-400/770)

Frame-level resource exhaustion no H/1.1 wordlist produces. Both are *availability*
findings, both strictly bounded here: we prove the **mechanism and the config gap**,
never the outage.

- **HPACK continuation flood:** a header block split across an endless run of
  `CONTINUATION` frames — the server buffers until `END_HEADERS` arrives, so
  unfinished streams pin worker/connection slots.
  - **Detect (config, passive):** limits present? `nginx http2_max_concurrent_streams`
    / `client_header_buffer_size`, envoy `max_concurrent_streams` /
    `max_headers_count`, LB/WAF in path (CloudFront/Akamai ship mitigations).
    No limits anywhere = candidate.
  - **Verify (bounded, capability only):** H2 actually served —
    `curl -s -o /dev/null -w '%{http_code}\n' --http2-prior-knowledge http://localhost:PORT/`.
    For a live mechanism check use nuclei's H2/CVE DoS templates **if installed**
    (02 toolchain), one default-size run against loopback: a split-header sequence
    getting served (vs immediate `PROTOCOL_ERROR`/`RST_STREAM`) = mechanism live.
    One run — no iteration ramping, no loops, loopback only, ever.
- **Rapid reset (CVE-2023-44487 class):** open a stream, cancel it (`RST_STREAM`)
  at once, repeat *on one connection* — gateways that don't account cancel rates
  per connection see fan-out multiply into backend load.
  - **Detect (config, passive):** envoy/haproxy rate settings, nginx conn/reset
    limits, cloud WAF/CDN in front (their mitigation is the control), HTTP/2 at
    all (if the listener is H/1.1-only, both H2 DoS families don't apply — say so).
  - **Verify (bounded):** a single localhost connection with ≤10 stream-cancels via
    an H2-capable client (nuclei H2 template or an `h2`/`hyper` script if present);
    the finding is *behavioral acceptance without rate accounting* — all 10
    accepted, no `GOAWAY` — confirmed in the target's logs afterwards. Never a
    sustained stream; one sequence, then stop.
- **Report:** `medium` (`tags: dos`) — high only when this listener is the
  deployment's single ingress with no upstream mitigation. Evidence = the config
  gap + one bounded mechanism run. Never report DoS from a flood you actually ran;
  remediation configs live in [06](06-remediation.md).

## Probe discipline

Everything here is **localhost only**, capped (≤13 requests total per desync run —
3 baseline + 5 families × 2 — ≤5 per cache/Host/CRLF/parser-diff probe, 1–2 timed
shots for ReDoS, one ≤10-hop redirect-loop chain, ≤3 CONNECT probes + ≤10 stream
cancels for the H2 families),
non-state-changing, marker
values only. Every desync/nc session closed; cache poisons purged and purge verified;
nothing left behind. Record request+response excerpts — these proofs are
header-level and belong verbatim in REPORT.md.

## Chaining ideas (Phase 4/5)

desync → auth bypass (front-door is the only gate) · Host poisoning → reset-link
takeover (03k) · cache poisoning → stored XSS (03a) · CRLF → session fixation (03b) ·
desync + cache = cross-user response leak (impact: `data-exposure`) ·
ReDoS + no worker limits = availability NO-GO for single-tenant deployments.
