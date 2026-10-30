# 03l — Traffic interception & HAR audit (WSTG-ATHZ-01 · CWE-598/319/200)

What the app *actually put on the wire* — the channel static analysis, SAST and
DAST never see. Tokens in URLs, cookies missing flags, credentials over cleartext,
CORS policies that trust the world, version banners, internal IPs in bodies: all
of it is only visible in a real capture. This file is **passive-first** — audit
captures you already own; interception targets are localhost-only (Phase 0 bounds).

**Scope boundary (non-negotiable):** everything here operates on (a) HAR files
you export from your own browser, (b) loopback traffic via a local proxy, or
(c) `curl --proxy` against a localhost target with user confirmation. **LAN MITM
is out of scope: no ARP spoofing, no SSL stripping, no sniffing traffic that is
not yours.** Interception on a network you don't own or administer is
unauthorized access, full stop — even when the Wi-Fi is open.

## Capture → audit workflow (passive, zero contact)

1. **Capture.** In Chrome/Firefox DevTools → Network → reproduce the flow →
   right-click → *Save all as HAR*. Or record through mitmproxy (below).
2. **Audit.** `node skills/mr-robot/scripts/har-audit.mjs capture.har` →
   findings-v1 JSON on stdout. Red flags to read first:
   - `jwt-in-query` / `secret-in-query` — URL query strings land in server logs,
     proxies, browser history, and `Referer` headers on every outbound link.
     A JWT in a URL is a finding even over perfect TLS (CWE-598).
   - `auth-over-cleartext` / `cookie-over-cleartext` — `http://` + credentials
     = anyone on the path reads them (CWE-319). Also check every `30x` target:
     an HTTPS hop that *redirects to HTTP* downgrades the session.
   - `cookie-missing-httponly|secure|samesite` — the three flags, one per risk:
     XSS pivot, cleartext replay, CSRF.
   - `cors-wildcard-credentials` / `cors-reflected-credentials` — `ACAO: *` with
     `Allow-Credentials: true` is broken policy (browsers reject `*`+credentials,
     but reflection + credentials = any origin reads authenticated responses,
     CWE-942). Verify live: a credentialed `fetch` from a foreign origin.
   - `credential-in-body` — form POST body; confirm the hop was TLS, then check
     the body never got logged (error pages that echo POST data).
   - `stale-session-token` — a session cookie/JWT present in the capture whose
     revocation story is unproven: replay it after logout and after a password
     change (03b §5) — an AiTM/phishing-stolen token that survives both is the
     whole account, MFA and all.
   - `version-header` / `private-ip-disclosure` — recon fuel: exact stack versions
     and RFC1918 topology leaks in JSON bodies.
3. **Merge into the scan.** `--append` folds HAR findings into an existing
   `findings.json` (ids continue after the current max, counts recomputed, one
   `har-audit` scanner row) — then score/SARIF/retest consume it like any other
   lane:
   ```
   node skills/mr-robot/scripts/har-audit.mjs --append TARGET/.mr-robot/run-*/findings.json capture.har
   node skills/mr-robot/scripts/score.mjs  TARGET/.mr-robot/run-*/findings.json
   node skills/mr-robot/scripts/sarif.mjs TARGET/.mr-robot/run-*/findings.json
   ```
4. **Verify before reporting.** Every rule is a *candidate*: replay the request
   with `curl -v` and confirm the header/flag/param is really on the wire (HARs
   lie — extensions, service workers, and DevTools re-fetching can mutate them).

## Local interception (loopback only)

`mitmproxy` installs via `setup-tools.sh`. Point *your own local app* at it —
never a network or host you don't own.

```
# 1. record a flow from a localhost app (its own traffic, loopback)
mitmdump -w flow.dump --listen-port 8080
#    then: HTTP_PROXY=http://127.0.0.1:8080 curl -sk http://127.0.0.1:8766/health
#    or launch your browser with a localhost-only proxy profile

# 2. export the flow as HAR for har-audit.mjs (mitmproxy ≥ 10 ships mitmproxy HarReader
#    as the 'hartool' addon; older versions: Flow Exporter → HAR via mitmproxy's API)
mitmdump -q --set hardump=har.dump flow.dump        # dump → HAR (addon-based)

# 3. replay exactly what was captured — no drift between "what I saw" and "what I send"
curl -sk --proxy http://127.0.0.1:8080 https://127.0.0.1:8766/health
```

- **curl --proxy** without mitmproxy: audit a single request's headers by just
  printing them — `curl -sv http://127.0.0.1:8766/ 2>&1 | grep -iE 'authorization|cookie|set-cookie'`.
- **HTTPS to localhost:** `curl -k` / browser exception for the fixture's
  self-signed cert (`app.py --tls`); testssl audits the cert while you audit the
  payloads (03i covers the TLS side).
- **Cookie/token leakage checklist:** grep the capture for every token the app
  issues (JWTs, session ids, API keys) and assert each appears **only** in
  `Authorization`/`Cookie` headers over HTTPS — never in URLs, referrers, page
  bodies, `localStorage`-echoed HTML, or analytics beacons.

## Capture hygiene (don't create a new finding while auditing)

A HAR is a full recording of a session — it contains your real credentials.

- Never commit HARs or `flow.dump` files; keep them in the git-ignored run dir
  or `/tmp`, and delete them after the audit (`rm capture.har flow.dump`).
- Before *sharing* a capture: strip cookies/tokens (`har-audit` output shows
  exactly which entries carry them), or re-capture with a throwaway account.
- The `--tls` fixture writes its demo key into git-ignored `.tls/` — same rule:
  runtime key material never leaves the machine (gitleaks allowlists it as
  runtime output, not as a secret to commit).

## Probe discipline

- Passive lane by default: a HAR audit makes **zero** network requests.
- Loopback interception (mitmproxy/curl --proxy) obeys the same bounds as the
  active lane: localhost only, explicit user confirmation, bounded requests,
  harmless marker traffic, cleanup + verification after.
- Never proxy traffic through this machine on behalf of third parties; never
  enable system-wide proxy/VPN redirection — scope it per-process.

## Chaining ideas (Phase 4/5)

- `secret-in-query` → the URL is in the access logs → chain to log-injection
  or log-storage exposure (03g) and rotate the leaked credential.
- `cookie-missing-secure` + any HTTP route → session replay from the wire
  (03b auth lane: confirm the session is actually accepted over HTTP).
- `cors-reflected-credentials` → authenticated cross-origin read → chain to
  CSRF-ish data exfil (03e) if a state-changing sibling endpoint exists.
- `private-ip-disclosure` → feed the RFC1918 targets into the SSRF lane (03c).
- `jwt-in-query` → the same JWT shape feeds the jwt_tool analysis (03b):
  weak `alg`, long-lived `exp`, shared secret strength.
