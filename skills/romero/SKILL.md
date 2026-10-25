---
name: romero
description: Browser traffic & storage auditor for a live product URL you own — drives a real browser (headless, or headed for manual login) and reports everything the browser saw and held: every network call (REST, GraphQL, WebSocket, SSE), request+response headers, security-header checklist, cookies and flags, localStorage/sessionStorage/IndexedDB/Cache Storage/service workers, manifest, tokens/JWTs, third-party contacts, console errors & CSP violations. Outputs REPORT.md + .har + capture.json, all local — nothing leaves the machine except loading the target. Use when the user says /romero, "audit my site's network calls", "inventory my APIs", "what does my app send to the browser", "capture this site's traffic", "browser storage report", "headers and cookies report", "give me a DevTools network and application report for this URL", or wants every request, header, cookie and storage entry on a product they own. Passive only — ordinary browser requests, never fuzzing; requires user confirmation the URL is theirs.
---

# romero — browser network & storage report

Named for Leslie Romero — fsociety's phreaker who knew the wires. This skill points a
**real browser** at a live product URL and records *everything* the browser sees and
holds — then renders it as a complete report: network calls, APIs, headers, cookies,
storage, sessions, tokens, third-party contacts.

Companion, not competitor: **`mr-robot`** tests whether the product can be *taken down*
(active red-team, localhost-gated). **`romero`** never attacks — it observes ordinary
browser traffic and reports what the app actually ships to the browser. If you need a
GO/NO-GO verdict, run `mr-robot`.

Everything is local and free: Node (built-in WebSocket/fetch, zero npm packages) plus
the Chrome/Brave already on the machine. No capture data, URLs, or tokens ever leave
the machine — the scripts make no network calls except loading the target URL itself.

## Phase 0 — bounds (before any capture)

1. **Confirm authorization.** The user names the URL and confirms it's theirs to test
   (their product / staging / with permission). Capture of a URL they don't own is
   out of scope — decline.
2. **Passive only.** The browser issues ordinary page loads; every request in the
   report is one a real visitor's browser would make. No fuzzing, no parameter
   mutation, no exploits — that's `mr-robot`'s job.
3. **Bounded.** `--budget` request cap (default 500, hard max 2000) and `--timeout`
   hard deadline (default 120s) stop the run on noisy pages. Scope is the entry URL
   plus any `--route` paths the user asks for — no crawling.
4. **Log in safely.** `--headed` opens a visible window and pauses: the *user* logs in
   manually (safe test account), presses Enter, capture proceeds. Credentials never
   touch the script. The browser runs in an **isolated temp profile** — never the
   user's real profile, cookies, or extensions.
5. **Third parties** load as the page itself requests them (CDNs, analytics — that is
   exactly what the report should surface); romero never probes beyond that.
6. **No destructive flows.** Capture navigates and waits — it never clicks
   purchases/deletions/submits. Tell the user to log into a safe account.

## Phase 1 — capture

```bash
node skills/romero/scripts/capture.mjs <url> \
  [--headed] [--route <path>]... [--out <dir>] \
  [--budget <n>] [--timeout <sec>] [--browser <path>]
```

Records (via the DevTools Protocol, system Chrome/Brave, headless by default):

- **Every network call** — method, URL, status, resource type, **full request and
  response headers**, bodies for XHR/fetch/document (capped), redirect chains, timing,
  HTTP version, disk-cache/service-worker provenance, failure reasons
- **WebSocket frames** (sent/received, capped) and **SSE events**
- **Cookies** — full jar before and after login, with Secure/HttpOnly/SameSite/Domain
- **Browser storage per origin** — localStorage, sessionStorage, IndexedDB
  (databases, stores, counts, sample keys), Cache Storage, service workers,
  `document.cookie`, the app manifest
- **Frames** (all iframes), **console output, JS errors, security log** (CSP
  violations, mixed-content warnings)

Outputs `<out>/capture.json` (schema `mr-romero-capture-v1`, raw values, no
redaction) and `<out>/capture.har` (HAR 1.2 — opens in any DevTools/HAR viewer).
Exit: `0` capture complete · `1` runtime failure · `2` usage/environment refusal
(no browser found, bad URL, budget/timeout invalid).

## Phase 2 — report

```bash
node skills/romero/scripts/report.mjs <out>/capture.json -o <out>/REPORT.md
```

Renders `REPORT.md`: 1 summary · 2 pages & frames · 3 API surface (grouped endpoint
templates, GraphQL operations, WS/SSE) · 4 request-header inventory · 5 response
headers + security-header checklist (CSP/HSTS/XFO/XCTO/Referrer-Policy/Permissions-
Policy/COOP/CORP + CORS + disclosure) · 6 cookie inventory with flags · 7 storage
dump · 8 tokens & credentials found in traffic (JWTs decoded locally) · 9 third-party
contacts and exactly what data they receive · 10 performance/caching/protocol ·
11 console, errors & security log · 12 observations + honest coverage gaps.

`REPORT.md` shows values **raw** (it stays on the user's machine). Section 12 is
advisory observations — romero issues no verdict; production-readiness calls belong
to `mr-robot`.

## Phase 3 — sanity check

```bash
bash skills/romero/scripts/selftest.sh [--quick]   # E2E against its own demo (port 8767)
```

Boots the bundled demo app from a temp copy, captures it, renders the report, and
gates every invariant — run before trusting a fresh install or before release.

## File map (progressive disclosure — load on demand)

| File | Load when |
|---|---|
| `references/01-report-structure.md` | Phase 2 — writing/verifying the report sections |
| `references/02-header-cookie-reference.md` | Phase 2 — security-header checklist & cookie-flag rules |
| `scripts/capture.mjs` | Phase 1 — capture options, CDP details, debugging |
| `scripts/report.mjs` | Phase 2 — grouping/redaction-free rendering logic |
| `scripts/selftest.sh` | Phase 3 — regression gates |
| `assets/demo/` | no URL at hand — bundled demo app for rehearsal |
