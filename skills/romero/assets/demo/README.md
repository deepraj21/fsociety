# romero demo fixture — INTENTIONALLY LOOSE, NEVER DEPLOY

Stdlib-only rehearsal target for the **romero** skill (its companion
`mr-robot` has its own fixture on port 8766; this one is **8767**).

```bash
python3 app.py            # → http://127.0.0.1:8767  (127.0.0.1 only)
# in another terminal:
node ../../scripts/capture.mjs http://127.0.0.1:8767 --out /tmp/romero-demo
node ../../scripts/report.mjs /tmp/romero-demo/capture.json -o /tmp/romero-demo/REPORT.md
```

## What one page load exercises

| Report section | Lane on this fixture |
|---|---|
| §3 API surface | `/api/user` (JSON + bearer), `/api/ping` (XHR), `/api/track` (form POST), `/redir` → `/final-page` (302 chain) |
| §3 WebSocket | `ws://…/ws` — server sends `hello-from-server`, echoes page's `hello-from-page` (marker round-trip) |
| §3 SSE | `/events` — `event: demo`, 3 messages then close |
| §4 request headers | `Authorization: Bearer <runtime-built JWT>` on `/api/user` |
| §5 response headers | **no** security headers at all → checklist rows all ❌ (by design), `Server` disclosure |
| §6 cookies | `demo_sid` (no flags), `trackid` (SameSite=Lax), `session` (no HttpOnly) — loose on purpose |
| §7 storage | localStorage (`apiToken`, `demoJwt`, `session_expires`), sessionStorage (`cart`), IndexedDB `romero-demo-db/sessions` (2 records) |
| §8 tokens | `apiToken` + decodable JWT in storage, bearer in header, `token` field in POST body |
| §9 third party | page pulls `http://localhost:8767/pixel.gif` while origin is `127.0.0.1:8767` — different host string = third-party row |
| §10/§11 | HTTP/1.0, uncompressed, 404 favicon, `console.error` line |

The live selftest (`scripts/selftest.sh`) boots this from a temp copy and
gates all of the above.
