# 03p — API transports: gRPC & server-sent events (CWE-346/200/639 · WSTG-ATHZ-01 · API4/API5:2023)

Two transport families whose auth and parsing never match the REST mental model —
REST-shaped probes slide right off them. gRPC speaks protobuf over HTTP/2 with
its own metadata headers; SSE streams until the connection closes and *cannot
send request headers at all*. Both are everywhere in modern APIs (grpc-gateway,
Envoy, Connect-RPC; `/events`, dashboards, live feeds) and absent from most
wordlists — this file is their test lane.

**Active-phase file:** localhost target + user confirmation + bounded probes.
`grpcurl` is used **if installed** (02 toolchain); everything else is source +
`curl`/netcat-level. No stream floods, ever.

## gRPC — detect first (Phase 1)

- **Detect (source):** `.proto` files (also `_pb2.py`, `.pb.go`, `buf.yaml`);
  server deps — `grpc`, `@grpc/grpc-js`, `google.golang.org/grpc`, `grpc-java`,
  `tonic`, `envoyoy/promises`-era PHP stubs; `grpc_server.Add_…`/`pb.Register…`
  handlers; grpc-gateway (`*.pb.gw.go`, `runtime.ServeMux`), Connect/Buf
  (`connectrpc.com`), Envoy `grpc_json_transcoder`/`http2` upstream config;
  health/reflection registration (`grpc.health.v1`, `reflection.Register`).
- **Detect (live, capability):** `curl -sI --http2-prior-knowledge http://localhost:PORT/`
  → `content-type: application/grpc+proto` on POST, or `PRI`-prefixed frames —
  an h2 listener that answers `application/grpc` = the transport is live.
- **Entry points for the attack surface:** every RPC = an endpoint wordlist no
  ffuf list produces — derive it from `.proto` *service* blocks (source) or
  server reflection (below).

## 1. Server reflection & schema exposure (recon — pairs with 01)

- **Detect:** `grpc.reflection.v1alpha.ServerReflection` registered (grpc-go/
  grpc-java defaults; many teams never disable it), `buf beta lint`/registry
  configs shipping to prod.
- **Verify (≤3 requests, if `grpcurl` installed):**
  ```
  grpcurl -plaintext localhost:PORT list            # services & methods
  grpcurl -plaintext localhost:PORT describe <svc>  # messages & fields
  ```
  Anything returned without credentials = full API surface + message schema to
  an unauthenticated caller — the gRPC twin of GraphQL introspection
  ([03j](03j-graphql-websocket.md) §1). Feed the method list into [01](01-recon.md)
  and run the authz rows below **per method** (a `UserService/Get` without an
  ownership check is BOLA in protobuf clothing — same class as 03j §2).
- **Impact:** recon (medium standing alone); the *method inventory* is what makes
  the authorization lane below systematic.

## 2. Transcoding differentials — JSON gateway ≠ proto backend (CWE-444/178)

The concrete instance of [03i](03i-http-protocol.md)'s parser-diff family: a
grpc-gateway/Envoy transcoder validates/parses **JSON**, the backend executes
**protobuf** — and the two disagree by design (proto3 defaults, unknown fields,
number handling). The security decision made on one side, the semantics of the
other.

- **Detect (source):** `grpc_json_transcoder`, `grpc-gateway` annotations
  (`google.api.http`), `envoy` `grpc_json_transcoder` filter, Connect's JSON
  mapping docs in-repo; any HTTP/JSON facade in front of `.proto` services.
- **Probe (≤6 requests, marker values):**
  1. **proto3 defaults:** omit a field the UI always sends (`role`, `admin`,
     `amount`) — backend may execute its *default* (0 / `""` / first enum) where
     the JSON layer's validation would have rejected absence.
  2. **duplicate keys:** `{"id":1,"id":2}` — gateway reads first, transcoder
     emits last (or vice versa): which id does the RPC use? Two `curl`s, one log line.
  3. **type coercion:** `"amount":"0"` (string) vs `0`, `"true"` vs `1` — does
     the transcoder coerce past a check the backend then interprets strictly
     (or the reverse — `0x10`, `1e2`, `-0`)?
  4. **unknown/repeated fields:** `{"is_admin":true}` on a message without it —
     silently dropped (fine) or does a *wrapper/dynamic* message keep it (A05-style
     mass assignment through the transcoder)?
  5. **int64/precision:** large ids as strings vs numbers (JS precision) — an id
     that *round-trips differently* than the one the authz check saw.
  6. **enums:** `role: "USER_EXTRA"` — proto accepts unknown-enum as `0` on some
     versions; check what the check saw vs what executed.
- **Prove:** capture both readings of ONE request — the gateway's log line/JSON
  response (what it validated) vs the backend's effect (what the RPC did, from
  the handler log or the marker's effect) — verbatim in the report, exactly as
  03i's differential prove rule demands. Chain to the concrete sink (authz skip →
  `authz-bypass`, traversal → 03c) — the differential alone is never the finding.
- **Impact:** authz/amount/id confusion across the translation seam; severity =
  the downstream interpretation.

## 3. Metadata vs HTTP header auth (CWE-287/346)

gRPC auth travels in **metadata** (`authorization`, `x-api-key`, custom `x-*`),
and gateways *translate or strip* — the seam is the bypass.

- **Detect:** auth middleware on the HTTP facade but none on `grpc.Server`/
  interceptor; `WithInsecure()`/`insecure.NewCredentials()` in server or client
  code; metadata readers (`md.Get("authorization")`) with no default deny;
  gateway `metadata` mappings in Envoy/nginx config.
- **Probe (≤6 requests):**
  1. call an RPC with **no** metadata → authenticated method must deny;
  2. same token in `authorization:` *header* vs metadata — do both pass, and does
     the *stripped* variant (gateway removes auth header, backend trusts
     `x-forwarded-*`-style metadata) pass with something a client controls
     (`grpcgateway-authorization` prefix quirks);
  3. cookie-only sessions: EventSource-style callers can't do cookies either —
     check whether the RPC falls back to an unauthenticated path or a static key.
- **Prove:** unauthenticated (or forged-metadata) call reaching a state-reading/
  changing method = `authz-bypass`/`authn-bypass`; ≤6 calls, marker metadata
  values only.
- **Bounds & tool:** `grpcurl` only if installed, `plaintext` localhost, ≤10
  requests total for the whole gRPC lane, describe/list once — no streaming
  methods invoked (a server-stream flood is DoS, forbidden by 03i's H2 rules).

## SSE — `EventSource` & `text/event-stream` (CWE-346/200/532)

The transport that *cannot* send headers forces apps into one of two bad options:
tokens in URLs, or blanket cookie+CORS — both are this lane.

- **Detect (source):** `EventSource(`, `text/event-stream`, `@sse`,
  `res.write("data:`, `event:`, `Last-Event-ID`, `/events`, `/stream`, `/feed`;
  nginx `X-Accel-Buffering: no`; framework SSE handlers (Spring `SseEmitter`,
  Rails `ActionController::Live`, Express `sse`/`text/event-stream` writers).
- **Probe (≤6 requests/streams, marker query values):**
  1. **Token-in-URL:** does the endpoint accept `?access_token=`/`?token=` (it
     must, for EventSource) — the token then lands in access logs, proxies, and
     browser history; grep the HAR the same way [03l](03l-traffic-interception.md)
     audits URLs, and check the emitted link isn't `Referer`-leaked. Token in a
     URL = `credential-exposure` even when the rest is perfect.
  2. **Connect-time authz:** `curl -N -H 'Origin: https://mr-robot-poc.example'
     http://localhost:PORT/events` — no Origin check + cookie auth = any page can
     *open* the victim's stream (CSWSH's sibling: forged-Origin subscribe).
  3. **Cross-origin read:** the stream's CORS (`Access-Control-Allow-Origin` on
     `text/event-stream`) — reflected origin *with* `Allow-Credentials` = any
     site reads the victim's live feed (event data = the payload; grade by what
     the events carry — balances, messages → high).
  4. **Replay via `Last-Event-ID`:** reconnect with `Last-Event-ID: 0` (or a
     forged id) — predictable ids + replay-on-reconnect without re-authz = event
     history to a caller who just needs a URL. ≤2 probes, read only the marker
     event's presence, not a sweep.
  5. **Reconnect amplification:** does each reconnect re-run an expensive query
     (the feed's `SELECT`) — note as config/DoS-adjacent (CWE-770) only if one
     probe shows it; never loop it.
- **Prove:** record the stream's first frames verbatim (headers + `data:` lines
  with marker events), the Origin/CORS behavior, and the token/URL story; every
  stream **closed in the same command** (`curl -N … --max-time 5`, `kill` the
  EventSource) — an open stream is a leaked session by the 03i discipline.
- **Impact:** connect-forgery → `csrf`-grade subscription actions; read-forgery →
  data leak (03o chains the *observation* half); token-in-URL → 03l/03b elevation;
  replay → event-history disclosure. Fix: per-event authz checks, Origin allowlist
  on connect, `no-store` on streams, short-lived one-time stream tickets (06).

## Probe discipline

Everything here is **localhost only** and capped: gRPC ≤10 requests (list/describe
once, ≤6 transcoding probes, ≤6 auth probes — overlapping budgets, one run),
SSE ≤6 requests with every stream closed in-command (`--max-time`), marker values
(`mr-robot-poc`) in query/metadata only, no streaming-method invocation, no
reconnect loops. `grpcurl` only if installed — capability-check first, record
skips as coverage gaps. Every differential/token/Origin result is `status:
candidate` until the two readings (or the leaked value) are captured verbatim and
reproduce twice.

## Chaining ideas (Phase 4/5)

Reflection method list (01) → per-method authz row (03j §2 class) → one BOLA
becomes the whole service · transcoding default/duplicate-key diff → authz/amount
confusion → 03e money/role impact · SSE token-in-URL → HAR discovery (03l) →
session replay (03b) · cross-origin stream read → live-oracle channel into 03o
XS-leaks (events as the bit stream) · metadata strip → unauthenticated RPC →
internal-service reach (03c).

## References

- gRPC ecosystem: proto3 language guide (field presence & defaults), grpc-gateway
  JSON mapping spec (duplicate keys, int64-as-string, enum handling), Envoy
  `grpc_json_transcoder` & gRPC metadata docs, grpc-go security docs
  (`insecure.NewCredentials()` warning)
- SSE: WHATWG HTML living standard — Server-sent events (`EventSource`,
  `Last-Event-ID`, reconnection semantics), MDN `text/event-stream`
- Related: [03i](03i-http-protocol.md) parser differentials · [03j](03j-graphql-websocket.md)
  introspection/BOLA parallels · [03l](03l-traffic-interception.md) token-in-URL ·
  [03o](03o-xs-leaks.md) cross-origin observation · [03b](03b-auth-gateway.md) session authz
