# 08 — Localhost daemons: when the target is a TOOL, not an app (CWE-346/306)

The perimeter nobody tests: **any page the user's browser opens may send requests to
`127.0.0.1`**. The browser's same-origin wall does not stop a request from *leaving* —
it only gates reading responses and non-simple requests. The actual walls between an
attacker page and a local daemon are exactly two things: **Origin/CORS checks the
daemon bothered to add, and auth it bothered to require.** Plenty of tooling adds
neither — it was written for a trusted desktop, not for the web.

Dev/AI tooling exploded this surface: **MCP bridges** (browser-control daemons that
hand shell/file tools to whoever can open a WS connection — the AIPex-class 2025
attacks drove 30+ tools from one malicious page), **Chrome DevTools** on
`--remote-debugging-port` (attach = evaluate in the user's browser session), Node
inspector `9229`, **Jupyter** (code exec *is* the product), webpack/vite dev servers
(HMR channels, source disclosure), Electron apps, database/web admin UIs.

**Attack story:** phishing email or a malicious docs site → page JS →
`ws://127.0.0.1:PORT/...` with a forged `Origin` → 101 → the daemon's full API,
running *on the victim's machine, inside their session*. No exploit, no memory
corruption — just an Origin check that was never written.

**Scope boundary (non-negotiable):** this lane only ever connects to loopback on
**your own machine** (the connect host is hardcoded in the script; `-p` takes digits
and ranges, never a hostname). It sends handshake/reflection probes only — the `101`
or the reflected header **is** the evidence; no frames, no payloads, no tool calls.

## The lane

```bash
# enumerate loopback listeners (lsof, fallback ss) → ≤3 requests per port
bash skills/mr-robot/scripts/daemon-sweep.sh

# target specific local ports (e.g. known dev-tool ports), custom WS path
bash skills/mr-robot/scripts/daemon-sweep.sh -p 9222,8765-8775 --ws-path /socket.io/?EIO=4
bash skills/mr-robot/scripts/daemon-sweep.sh --out sweep.json     # mr-robot-daemon-sweep-v1
```

Exit: `0` no foreign-origin acceptance · `1` hijackable daemon found (candidate —
confirm the daemon doesn't *document* intentionally open browser access before
reporting) · `2` usage · `3` nothing enumerable (no `lsof`/`ss`, or no listeners).
Bounded: ≤40 ports, ≤3 requests/port, 2s default timeout, `--noproxy '*'` +
no-redirect so the probe can never leave loopback.

## Finding classes (what the sweep reports)

| Class | Signal | Severity | Why it matters |
|---|---|---|---|
| `ws-open-origin` | WS upgrade → `101` with forged Origin | **high** | full-duplex API from any page: MCP tool calls, HMR, editor channels |
| `ws-open-origin(devtools)` | 101 on the `/devtools/...` target path | **high** | evaluate in the attached browser = session takeover (report, never evaluate) |
| `cors-origin-reflected` | `ACAO` echoes the foreign Origin (+creds = high) | medium/high | any page **reads** the daemon's responses |
| `cors-origin-star` | `ACAO: *` | medium | reads + simple `POST` allowed cross-origin (local daemons carry no cookies to protect — the response *is* the loot) |
| devtools target list on `GET /` | `webSocketDebuggerUrl` in body | info (surface) | note the surface + its origin policy state; modern Chrome origin-gates attach (`--remote-allow-origins`) — verify, don't assume |

## Detect (source side — Phase 1)

- Ports and flags in dev scripts/compose: `--remote-debugging-port`, `--inspect`,
  `jupyter notebook --ip`, `webpack-dev-server --port`, `vite --port`, Electron
  `BrowserWindow.webPreferences`.
- MCP/desktop-bridge configs: `mcp*.json`, `.vscode/launch.json`, `devcontainer.json`,
  app configs with `"port"` / `"url"` pointing at `127.0.0.1`.
- Listeners with no business being browser-facing: run the sweep in Phase 1 anyway —
  forgotten daemons (yesterday's debug session still on 9222) are findings too.

## Verify → Prove (marker-grade, localhost only)

1. Run the sweep; treat every hit as a **candidate**.
2. Confirm from a *browser context*: a local test page (served from localhost) doing
   `new WebSocket('ws://127.0.0.1:PORT/...')` — if it opens with a foreign `Origin`
   and completes **one harmless read** (list/health/status), that's the proof.
   **Never** invoke a mutating tool call, never `evaluate` on a DevTools target —
   proving the door opens is the entire PoC.
3. Record: request line, `Origin` sent, `101`/ACAO received, daemon version banner.
   Verbatim excerpts belong in REPORT.md (`status: candidate` until step 2).

## Impact

- MCP bridge with shell/file tools → page = **RCE chain** (`tags: rce-chain`, NO-GO
  when confirmed): the tool runs with the user's privileges from a web origin.
- DevTools/inspector open → read cookies/localStorage, drive the logged-in browser
  session, execute in page contexts.
- Jupyter without token / weak token → arbitrary code execution (it is a kernel).
- Dev server exposed → source + `.env` disclosure, HMR channel abuse history.

## Remediation (06 has the patterns)

Bind `127.0.0.1` explicitly (never `*`/`0.0.0.0` for tools), check `Origin` against
an allowlist **and** require a token/header the page can't guess (Jupyter's token,
dev-server `allowedHosts`/`headers`), kill debug ports when not debugging, upgrade
to tool versions that origin-gate (Chrome ≥111 does by default). A tool that needs
*no* browser clients should reject every `Upgrade`/`Origin` outright.

## Chaining

XSS on any site the user visits (03a) → this lane = sandbox escape to local files/
shell · malicious dependency's install script starts a listener → survives the
build (03d) · HAR capture (03l) revealing local daemons during dev sessions.
