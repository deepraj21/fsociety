# 05 — Attack playbook: enumeration, fuzzing & exploitation of the live product

**Phase 2 & 4 tooling.** Source code shows what *should* exist; this playbook attacks
what the product *actually exposes* and shows how to chain tools into an exploit path.
Everything here is free & local. **Phase 0 gate applies: local instance only, user
confirmed, non-destructive, ≤5 req/s, logs every probe to the attacker notebook.**

```bash
# one-time: installs ffuf feroxbuster httpx katana arjun sqlmap (free OSS)
bash skills/mr-robot/scripts/setup-tools.sh
export TARGET=http://localhost:PORT
```

## 1 — Fingerprint: what is actually serving?

```bash
httpx -u "$TARGET" -status-code -title -tech-detect -server -json -silent
curl -sI "$TARGET"                     # headers: server, x-powered-by, cookies, CSP
```
Record: framework + version, reverse proxy, server software, cookie flags, tech
versions → outdated runtime / EOL framework = immediate finding (A03:2025), and the
version tells you which exploit class to prioritize (03a/03g).

## 2 — Crawl: let the product reveal its own map

```bash
katana -u "$TARGET" -d 3 -jc -silent -o crawl.txt     # JS-aware crawl, 3 depth
```
`crawl.txt` = discovered URLs. Also mine **source maps & bundles** (the richest
endpoint source in modern apps):

```bash
grep -rhoE '"/[a-zA-Z0-9/_-]{2,}"' dist/ public/ static/ 2>/dev/null | sort -u > js-endpoints.txt
grep -rhoE 'https?://[^"'\'' )]+' dist/ static/ 2>/dev/null | sort -u   # internal URLs, APIs
```

## 3 — Brute-force discovery: directories & forgotten endpoints

```bash
ffuf -u "$TARGET/FUZZ" -w skills/mr-robot/assets/wordlists/paths.txt \
     -mc all -fs 0 -t 10 -rate 5 -of json -o ffuf-paths.json -s
feroxbuster -u "$TARGET" -w skills/mr-robot/assets/wordlists/paths.txt \
     -t 5 --rate-limit 5 -o ferox.txt --json   # alternative/complement
```

What matters (verify each in source afterwards):

| Found | Why an attacker cares | Catalog |
|---|---|---|
| `/admin`, `/internal`, `/debug`, `/console` | privileged surface, often weakly gated | 03b |
| `/swagger`, `/openapi.json`, `/graphql`, `/.well-known/` | full API inventory (API9:2025) | 01/03e |
| `/backup*`, `/*.bak`, `/.git/HEAD`, `/.env` | direct secret/data exposure | 03c |
| `/metrics`, `/actuator`, `/health` | internal info leak → pivot fuel | 03g |
| endpoints in live but **not** in source | shadow/undocumented routes — test them hardest | 03e |
| endpoints in source but **not** live | version drift — attack the *older* exposed one | — |

## 4 — Parameter discovery: where the payloads go

```bash
arjun -u "$TARGET/api/item" -m GET JSON --qs -o arjun-item.json   # hidden params
ffuf -u "$TARGET/search?FUZZ=test" -w skills/mr-robot/assets/wordlists/params.txt \
     -mc all -fs <baseline-size> -t 5 -rate 5 -s
```
Baseline trick: send one request with a bogus param, note the response size/time; a
param is *live* when the response changes. Any live param on an interesting endpoint →
feed it straight to step 6. **Non-HTTP targets** (native CLI, file parser, local
daemon): skip the ffuf lane — fuzz the input directly per
[09-fuzz-binary.md](09-fuzz-binary.md) (`fuzz-lane.mjs`).

## 5 — Build the target list (notebook → next phase)

Merge crawl + ffuf + ferox + JS mining + source routes into one target list, each row:

```
METHOD PATH PARAMS AUTH? SOURCE(live/source/js) HYPOTHESIS(catalog test) PROBED?(y/n)
```

This list **is** Phases 3–4's work queue. Source-only endpoints get static verification;
live-only endpoints get active probing.

## 6 — Exploit the enumerated surface (harmless-marker payloads only)

Per endpoint, pick the class from its shape — catalogs 03a–03p have the full test
steps. Fast patterns:

```bash
# SQLi — mechanism proof, then STOP (no data pulls):
curl -s "$TARGET/api/item?id=1'"               # error/behavior change?
curl -s "$TARGET/api/item?id=1%20AND%201=1"    # vs id=1%20AND%201=2 → blind proof
sqlmap -u "$TARGET/api/item?id=1" --batch --level 1 --risk 1 --technique T --threads 1

# SSTI / code injection — expression proof only:
curl -s "$TARGET/page?name={{7*7}}"            # 49 → injected expression executed

# Command injection — marker only:
curl -s "$TARGET/run?host=127.0.0.1%3Becho%20mr-robot-poc"   # marker in output

# XSS — reflected-payload proof:
curl -s "$TARGET/search?q=%22%3E%3Cscript%3E/*mr-robot-poc*/%3C/script%3E"

# Authz on a live admin endpoint (two test accounts, 03b §3):
curl -s -H "Cookie: $USER_A_COOKIE" "$TARGET/admin/users"    # B's/admin's data back?

# SSRF:
curl -s "$TARGET/fetch?url=http://127.0.0.1:PORT/admin"     # internal page returned?
```

Nuclei sweep of everything (already wired into `scan-all.sh --live`):

```bash
nuclei -u "$TARGET" -l <(cat crawl.txt ffuf-paths.json | head -500) \
       -severity critical,high,medium -rate-limit 5 -duc -jsonl-export nuclei-live.jsonl
```

**Discipline:** ≤10 probes per endpoint-class before you move on; marker payloads only;
bounded time-based payloads (`SLEEP(2)` once — never loops); anything that would
modify/destroy data is demonstrated *on paper* instead, unless the user explicitly
approved that exact test in Phase 0.

## 7 — Tool-chaining patterns (the actual pentest loop)

Real engagements are chains, not tool runs. Recurring patterns:

1. **Enumerate → verify → exploit:** ffuf finds `/api/internal` (absent from source) →
   read the route handler → no auth decorator → send marker request → `auth-bypass` (NO-GO).
2. **Leak → pivot:** JS bundle leaks an internal hostname → SSRF param reaches it (03c)
   → internal admin reachable → account takeover chain. Record as ONE finding, tag the end state.
3. **Fingerprint → known-vuln:** tech-detect says `framework X vOld` → check its known
   issue class in the catalog → confirm against *your* config before claiming it.
4. **Scanner hit → live proof:** bandit/semgrep flags a sink → find its route via the
   target list → prove with one marker request → static+dynamic confirmed = high confidence.
5. **Business flow abuse:** enumerate the flow's API (step 3–4) → replay it out of order
   / in parallel directly against the API, bypassing the UI (03e).
6. **Failure → notebook → hypothesis:** a rejected probe is data — update the mental
   model (that path is validated, that param is sanitized) and aim the next probe where
   it isn't.

## 8 — Coverage honesty

If a tool is missing or a phase couldn't run (no running instance = no Phase 2/4),
say so in the report's coverage ledger — **never claim a test you didn't perform.**
