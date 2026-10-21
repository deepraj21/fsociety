# 03j — GraphQL & WebSocket attacks (API3/API5:2023 · WSTG-ATHZ/ATHN · CWE-639/400/346)

Two protocol surfaces with their own authz model — both frequently tested with
REST habits and therefore under-tested. **Active-phase file:** localhost target +
user confirmation + bounded queries (depth ≤4, batch ≤10) only.

## GraphQL — find it first

- **Detect (static):** `graphene`, `strawberry`, `ariadne`, `graphql-js`/`express-
  graphql`/`apollo-server`, `gqlgen`, `ruby-graphql`, `graphql-ruby`; schema files
  (`schema.graphql`, `*.graphqls`); any `/graphql` route or `POST /` with
  `query` in body.
- **Detect (live, Phase 2):** `ffuf -u http://localhost:PORT/FUZZ -w paths.txt`
  hits on `/graphql`, `/graphiql`, `/playground`, `/altair`, `/voyager`; a
  GET-with-`?query=` that returns JSON with `"data"`/`"errors"`.

## 1. Introspection & explorer exposure — WSTG-ATHZ, API5

- **Prove (passive-ish, 1 request):**
  ```
  curl -s -X POST http://localhost:PORT/graphql \
       -H 'Content-Type: application/json' \
       -d '{"query":"{__schema{types{name,fields{name}}}}"}'
  ```
  Full schema back = full API map in one shot (medium alone; feeds every test below —
  treat as instant Phase-2 enumeration win). GraphiQL/Playground *served to anyone*
  is a finding on its own (bundled explorer + introspection = interactive API IDE
  exposed). In production config, introspection should be disabled — check the
  repo's env/gating (`INTROSPECTION` flag, `debug` mode gating).
- Note honestly in the report: some teams introspect-only-in-dev by design; the
  finding is *dev tooling reachable from the running local instance* + whether the
  same gate exists in the deploy config.

## 2. Field-level authorization gaps (BOLA in GraphQL clothing) — CWE-639

REST tests endpoints; GraphQL tests **fields** — the authz check must be per-resolver.

- **Method (two accounts, as in 03b):** enumerate types from introspection; pick
  sensitive fields (`user.ssn`, `user.email`, `adminFlag`, `paymentMethod`) and
  query them for *another* user's node id:
  ```
  curl -s -X POST http://localhost:PORT/graphql -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $TOKEN_A" \
    -d '{"query":"query{user(id:\"<B_id>\"){id,email,role}}"}'
  ```
  Data returned = **horizontal BOLA, high** (API3:2023). Same pattern via nested
  edges: `orders { user { email } }` often leaks through the *other* side of the
  relationship even when the direct field is guarded.
- **Verify in source:** every resolver touching a user-scoped object must call the
  authz check with *both* the viewer and the object id — find resolvers that only
  check "logged in".
- **Mass-assignment cousin (API3/API6):** mutations accepting full type shapes —
  `updateUser(input:{role:"ADMIN"})` sets fields the UI never shows (03e BOPLA).

## 3. Query batching & alias abuse — CWE-770 (rate-limit bypass)

- **Batching:** arrays of operations in one HTTP request — N logins per round-trip
  defeats naive per-request rate limits:
  ```
  curl -s -X POST http://localhost:PORT/graphql -H 'Content-Type: application/json' \
    -d '[{"query":"mutation{login(u:\"admin\",p:\"a\"){token}}"},
         {"query":"mutation{login(u:\"admin\",p:\"b\"){token}}"}]'
  ```
  If the limiter counts 1 while 10 logins land → rate-limit bypass (**medium-high**,
  chains with dictionary attack from 03b). Keep batch ≤10 and total attempts within
  the credential caps.
- **Aliases:** `a1: login(...), a2: login(...)` … same effect, single query document.
- **Cost-amplification:** aliases on *expensive* fields (`p1:users{...}, p2:users{...}`
  × 50) — one query, 50× resolver work. Probe with ≤10 aliases and time it; growth
  is the proof. Do not scale the probe.

## 4. Denial-of-service via nesting — CWE-400 (bounded)

- **Prove:** one deeply-nested query (depth ≤4 is our cap on the wire) against a
  self-referential field (`user{friends{friends{friends{...}}}}` or circular
  `category{children{children{…}}}`), timed like the ReDoS shot in 03i:
  ```
  curl -s -o /dev/null -w '%{time_total}\n' -X POST http://localhost:PORT/graphql \
    -H 'Content-Type: application/json' -d '{"query":"{a:__typename b:__typename ...}"}'  # ×N aliases
  ```
  Growing time with depth/alias count = unbounded resolver recursion (**medium**;
  the app should cap depth/complexity — graphql-depth-limit, query complexity
  analysis). Kill slow requests; never send a real depth bomb.

## 5. Mutation & subscription specifics

- **Unauthenticated mutations:** `register`, `updateRole`, `deleteUser`, password
  reset resolvers callable without auth — static sweep of the schema's mutation
  names vs the authz middleware list (same "missing decorator" method as 03b).
- **Error-message leaks:** verbose GraphQL errors (`Cannot query field "ssrN" on
  type "User"` + stack traces + SQL text) — info-leak feeding injection (03a).

## WebSocket — CSWSH & message-level authz (CWE-346/639)

- **Detect:** `ws://`, `socket.io`, `WebSocket(`, `graphql-ws`, `actioncable`,
  `sockjs`, `/ws` routes; upgrade handlers in server code.
- **Cross-site WebSocket hijacking (CSWSH):** the WS handshake carries cookies;
  does the server check `Origin`?
  ```
  # from a page you control in a real browser session — or prove statically:
  grep -rn "origin" <ws-handler>   # missing Origin check + cookie auth = CSWSH (medium-high)
  ```
  If cookies authenticate the upgrade and `Origin` is unchecked, a malicious page
  rides the victim's session over WS → **confirmed** when the accepted connection
  returns the victim's data stream (prove with the marker account locally).
- **Handshake auth:** token in querystring (`?token=`) leaks via logs/Referer —
  low-medium; prefer `Sec-WebSocket-Protocol` or first-message auth.
- **Message-level authz:** after upgrade, do subscription/channel payloads check the
  viewer per message? `subscribe(channel:"user:<B_id>")` with A's token = IDOR on the
  stream (same two-account method). Channel-id guessability = finding.
- **Unsubscribe/flood bounds:** one bounded burst only (≤10 msgs), never sustained
  floods (Phase 0 rate rules apply to WS too).

## Probe discipline

Localhost only; introspection 1 request; batch ≤10; alias/depth probes ≤10 units and
time-boxed (kill slow curls, record the growth, stop); two-account tests restore any
state changed (role resets, test deletions rolled back — verify). Everything
request/response-excerpted into the notebook and REPORT.md.

## Chaining ideas (Phase 4/5)

introspection → full field map → BOLA sweep · batching → rate-limit bypass →
dictionary attack (03b) · mass-assignment mutation → privilege escalation (`authz-
bypass`) · CSWSH + session cookie → live data stream (`data-exposure`) ·
error-leak SQL text → precise SQLi (03a) · nesting DoS + no gateway timeouts =
availability finding for single-tenant deploys.
