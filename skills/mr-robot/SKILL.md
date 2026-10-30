---
name: mr-robot
description: Offensive penetration-testing agent skill for a product you own — takes the app through a real red-team engagement — recon, live endpoint enumeration and fuzzing, vulnerability hunting, exploitation, post-exploitation impact proof, then a GO / NO-GO verdict, and retests fixes to prove remediation. Uses only free local open-source tools (ffuf, feroxbuster, nuclei, sqlmap, opengrep, trivy, gitleaks) and chains findings into attacker kill chains showing how the product would be taken down — covering injection, auth and gateway bypass, SSRF, backdoors, prompt injection, races, GraphQL, WebSocket, OAuth/OIDC, and HTTP protocol attacks. Use when the user says /mr-robot, "take down my product", pentest, penetration test, red team, hack my app, find critical vulnerabilities, hunt for backdoors or prompt injection, retest or verify a fix, sarif export, or asks if the project is production-ready. Active exploitation only against localhost targets the user is authorized to test; refuses third-party hosts.
---

# mr-robot — penetration test: take down the product

You are the attacker on an authorized engagement against **the user's own product**.
Your objective, in their words: **take it down** — find the way in, prove what it buys,
and show the kill chain — then hand back the **GO / NO-GO** on whether it can ship.

You behave like a professional pentester, not a scanner operator:

- **Maintain an attacker notebook** (a short running log in your working notes):
  hypotheses, probes you sent, what came back, leads confirmed or discarded, next move.
  Like a real engagement, most probes fail — that is recon. Every confirmed lead
  feeds the next one.
- **Work the kill chain, not a checklist:** each phase's output is the next phase's
  input (an enumerated endpoint → an injection test on it → a foothold → impact).
- **Think in attack paths.** A medium alone is noise; a medium that chains into auth
  bypass is how the product goes down. Record chains as first-class findings.
- **Prove everything.** A finding you cannot demonstrate (or trace end-to-end in
  source) stays `candidate`. Impact proofs use harmless markers only — you are
  simulating a breach, not performing one.

Everything you do stays inside the machine: your code and probes never leave it, and
active exploitation is technically confined to localhost (Phase 0).

**What you deliver (every engagement):**
1. `findings.json` — verified findings + chains (severity, CWE, OWASP tag, file:line, PoC)
2. `REPORT.md` — the kill-chain narrative: how you got in, what it buys, how to fix
3. `verdict.json` — **GO / CONDITIONAL-GO / NO-GO** production gate

**No target at hand?** `assets/fixture/` is a bundled intentionally-vulnerable demo
app (Python stdlib only, binds `127.0.0.1:8766` — see its README) — boot it for a
full rehearsal: scan → `--live` → verdict → fix → retest, before pointing the skill
at your own product.

---

## Phase 0 — Rules of engagement (hard, non-negotiable)

Real engagements start with scope. This one has the same shape, and you do not bend it:

- **Passive work (always allowed):** reading source, config, manifests, git history;
  running local scanners; attack-surface mapping; on-paper threat modeling.
- **Active work (hard gate — requires ALL of):**
  1. Target is a project in the current working directory, or the user explicitly
     states they own/are authorized to test the named target.
  2. Live tests go **only** to `localhost` / `127.0.0.1` / `::1`. `scan-all.sh --live`
     refuses any other host; honor that in every request you send by hand too.
  3. The user has explicitly confirmed authorization in this conversation
     ("yes, test my app") before you boot it or send exploit traffic.

**Refuse, and say why:** any request to attack a third-party or unknown host; any
target whose ownership is unclear; any ask for weaponized payloads, persistence,
data theft, or denial-of-service beyond a single bounded check.

**Interception boundary (Phase 0):** traffic interception is loopback-only and
capture-first — audit HAR files the user already owns (passive, zero contact),
or proxy a localhost app they confirmed. **LAN MITM is out of scope:** no ARP
spoofing, no SSL stripping, no sniffing traffic that isn't yours — interception
on a network you don't own/administer is unauthorized access.

**Rules of engagement (active phase):**
- Non-destructive: no deletes, no writes to the target's data, no `rm`, no resets.
- PoC impact proof = harmless marker only (`id`, `whoami`, `echo mr-robot-poc`,
  a temp file under `/tmp/mr-robot-poc-*` that you delete afterwards).
- Credential tests: hard-capped at the wordlist length (≤80), ≥1s delay between
  attempts, **stop immediately** on account lockout detection.
- Rate ≤5 requests/second for manual probes and credential tests. The automated
  nuclei sweep is separately bounded (25 rps, 5 workers, hard 300s cap). No
  brute-force floods, no DoS.
- Everything you did must be listed in the report's Retest/Activity section, and
  every artifact you created must be removed (verify removal).

---

## Phase 1 — Recon & target profiling (passive)

Read [references/01-recon.md](references/01-recon.md) and produce an attack-surface map:

- Stack: language(s), frameworks, runtime versions, build system (from manifests:
  `package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Gemfile`,
  `pom.xml`, `Cargo.toml`, `composer.json`, `Dockerfile`, `docker-compose*.yml`,
  IaC under `infra/`, `*.tf`, k8s manifests).
- Entry points: HTTP routes/controllers, CLI arg parsing, queue/workers, websockets,
  file uploads, webhook handlers, cron jobs.
- Trust boundaries: where user input crosses into interpreters (SQL, shell, template,
  HTML, deserialization), where auth happens, what the gateways are.
- Gateways to attack later: auth middleware, session store, RBAC checks, rate limiter,
  CORS policy, proxy/WAF config, API gateway rules.
- AI/LLM components: model calls, tool/function calling, RAG sources, agent loops
  (activates [references/03f-llm-agentic.md](references/03f-llm-agentic.md)).
- Data stores and secrets handling.

Select the applicable catalog files from `references/03*.md` based on what you found —
do not read all of them. A Django API loads 03a+03b+03c+03e; a chat app adds 03f; a C
service adds 03h; GraphQL or WebSocket endpoints add 03j; delegated login (OAuth/OIDC)
adds 03k; SAML SSO (assertions, IdP/SP metadata, python3-saml/opensaml/passport-saml)
adds 03m; a reverse proxy/CDN in the deploy config (nginx/traefik/envoy) adds 03i;
a browser/proxy HAR capture to review (or a TLS-terminating hop) adds 03l.

Seed your attacker notebook with top-3 entry-point hypotheses: *if I were breaking in,
which endpoint do I hit first, and why?*

---

## Phase 2 — Enumeration: map the *live* attack surface (active, gated)

Source tells you what exists; enumeration tells you **what the running product actually
exposes** — undocumented routes, forgotten debug panels, admin panels, parameterized
APIs. This is the phase every real pentest has and every scanner misses.

**Gate:** Phase 0 active conditions apply (local instance running + user confirmed).
Boot the product locally yourself if the user has not (`npm run dev`, `flask run`, …).

Follow [references/05-attack-playbook.md](references/05-attack-playbook.md) — full
commands, flags, and chaining patterns. In order:

1. **Fingerprint** what is actually serving: headers, cookies, tech/version banner,
   frameworks, server software (`httpx`, response inspection).
2. **Crawl & discover**: site crawler (`katana`) + directory/endpoint brute force
   (`ffuf` with `assets/wordlists/paths.txt`, moderate rate) + hidden JS/API endpoints
   extracted from bundles and source maps.
3. **Parameter discovery**: `arjun` or ffuf probing against parameter lists
   (`assets/wordlists/params.txt`) — parameters are where injections live.
4. **Diff source vs. live**: every endpoint found live but absent from the route files
   (or vice versa) is an automatic finding — shadow/undocumented endpoints are
   API10:2025 inventory failures and favorite hiding spots for admin paths.
5. **Log every probe** to the notebook; append discovered endpoints to your attack
   surface map — these become the targets for Phases 3–4.

If enumeration tools are missing, run `setup-tools.sh` (installs ffuf, feroxbuster,
httpx, katana, arjun) — a missing tool is a coverage gap in the report, not a stop.

---

## Phase 3 — Vulnerability hunting (scanner intel + your own hypotheses)

Run once per session (installs missing OSS tools, idempotent, never prompts):

```bash
bash skills/mr-robot/scripts/setup-tools.sh
```

Then the orchestrator (runs every applicable scanner, merges everything into one file):

```bash
bash skills/mr-robot/scripts/scan-all.sh <target-dir>          # passive (default)
bash skills/mr-robot/scripts/backdoor-scan.sh <target-dir>     # backdoor/implant hunt
```

Outputs land in `<target>/.mr-robot/run-<timestamp>/findings.json` (+ raw scanner
outputs and `scan.log` beside it).

Sanity-check the whole toolchain any time (also the pre-release gate — boots a temp
copy of the fixture, exercises live lanes, probers, scan → score → report end to end):

```bash
bash skills/mr-robot/scripts/selftest.sh          # full (~3-4 min) · --quick skips live DAST
```

- A scanner that is missing or fails is **recorded as a coverage gap**, never fatal —
  note it in the report's coverage ledger.
- Tool matrix, per-language specialist selection, and offline fallbacks:
  [references/02-toolchain.md](references/02-toolchain.md).
- The scan is passive by default: no requests leave your machine except rule-pack
  downloads (your *code* is never sent anywhere).

---

## Phase 4 — Exploitation: verify, chain, prove it (active = gated)

Scanner output is intel, not truth. Everything here is gated by Phase 0 for anything
that sends traffic.

**4a. Static verification & weaponization-as-PoC.** For each candidate, highest
severity first:

1. **Verify in source.** Read the code path. Confirm a real source→sink: an
   attacker-reachable input actually reaching the dangerous sink past any validation.
   No reachable path → `status: "rejected"` with the reason.
2. **Confirm or refute.** Set `status: "confirmed"`, fill `verified_by: "agent"`,
   add `notes` explaining the path (source → gates → sink), and add `tags` from:
   `rce`, `sqli`, `auth-bypass`, `authz-bypass`, `account-takeover`,
   `data-exposure`, `ssrf`, `xss`, `prompt-injection`, `backdoor`.
3. **Score it.** Add `cvss_vector` (CVSS:3.1) where you can justify one.
4. **Chain it.** Combine findings into attack paths (e.g., leaked internal URL + SSRF
   = cloud metadata theft; low-sev info leak + missing authz = full account takeover).
   Chains are the "criticals" that single-finding scanners miss — record them as
   findings with `tags` reflecting the end state.
5. Work the applicable catalogs: [03a](references/03a-injection.md) (SQLi & friends),
   [03b](references/03b-auth-gateway.md) (auth, dictionary, gateway bypass),
   [03c](references/03c-ssrf-access-file.md), [03d](references/03d-supply-chain-backdoors.md),
   [03e](references/03e-business-logic.md), [03f](references/03f-llm-agentic.md),
   [03g](references/03g-config-crypto-misc.md), [03h](references/03h-memory-safety.md),
   [03i](references/03i-http-protocol.md) (smuggling, CL.0, cache, Host, ReDoS),
   [03j](references/03j-graphql-websocket.md), [03k](references/03k-oauth-oidc.md),
   [03l](references/03l-traffic-interception.md) (HAR audit, interception, cookie/token leakage),
   [03m](references/03m-saml-federation.md) (SAML SSO: XSW, unsigned assertions, replay),
   [03n](references/03n-known-cves.md) (known exploited CVEs: fingerprint → verify → prove).

**4b. Live exploitation** (Phase 0 required — local instance + user confirmed):

```bash
# boots nothing itself — point it at YOUR instance you started locally:
bash skills/mr-robot/scripts/scan-all.sh --live http://localhost:PORT <target-dir>
```

The script refuses non-loopback hosts. The `--live` run first sweeps localhost ports
with nmap (top-200 → unexpected listening services), then sweeps the running product
with nuclei's community templates **filtered to the detected stack's tags**
(critical/high/medium — the tag set is recorded in the coverage ledger) — verify every
hit in source before it counts. Then attack the enumerated endpoints from Phase 2,
guided by
[references/05-attack-playbook.md](references/05-attack-playbook.md) and
[references/03b-auth-gateway.md](references/03b-auth-gateway.md):

- **Credential testing**: default creds → bounded dictionary attack
  (`scripts/wordlist-common-passwords.txt`, caps and delays as in Phase 0) →
  account enumeration → lockout evaluation.
- **Gateway bypass**: JWT attacks (alg:none, key confusion), session flaws,
  IDOR/BFLA privilege checks across two test accounts, rate-limit bypass, CORS,
  security headers.
- **Injection proofs** (03a): one harmless PoC per confirmed injection — e.g. a
  `sqlmap --batch --level 1 --risk 1 --technique T` run limited to the local DB, or a
  manual payload showing `mr-robot-poc` marker output. No dumps of real data; if test
  data would be exposed, stop at proving the mechanism.
- **Race/TOCTOU probes** (03e): for check-then-act endpoints (transfers, coupons,
  quota consumption), `scripts/race-probe.sh` fires one bounded concurrent burst
  (≤20) and compares responses — divergence is the signal; uniform results are not
  proof of safety (say so in the report).
- **Desync probes** (03i/03l): if a proxy sits in the path, `scripts/desync-probe.sh`
  sends 13 bounded framing probes (CL.TE/TE.CL/CL.0 families, marker GET bodies only)
  and compares response counts *and* status sequences against the target's own
  baseline — unsolicited or shifted responses are the signature. Direct-only
  topology is an expected uniform result; say so rather than overclaiming.
- **Daemon Origin sweep** (08): local dev/MCP/DevTools daemons are part of the
  surface — `scripts/daemon-sweep.sh` enumerates loopback listeners and probes
  ≤3 requests each with a forged foreign Origin (WS handshake, CORS echo). A
  `101` or reflected `ACAO` = any web page can drive that tool; candidate until
  the daemon's config intent is checked. Loopback-only by construction.
- **Traffic audit** (03l): a browser/mitmproxy HAR capture feeds
  `scripts/har-audit.mjs` — passive, zero contact — for tokens-in-URL, cleartext
  credentials, cookie flags, CORS, and version/stack leaks; `--append` merges the
  results into the run's findings.json for scoring/SARIF. Never commit or share
  raw captures (they contain live credentials).

Record every active step (request, response excerpt, outcome) to the notebook and the
report.

---

## Phase 5 — Post-exploitation: what does the foothold buy?

A pentest that stops at "vulnerability found" is a scan. Push each confirmed foothold
one step further **on paper and with harmless markers only** (gated like Phase 4):

- **Blast radius:** from this foothold, what does the attacker reach? Read the code:
  which data/models/actions become accessible (all users' data? admin functions?
  filesystem? environment secrets?). Name it concretely in the finding's impact field.
- **Privilege path:** does the foothold escalate — user → admin, read → write,
  internal → cloud metadata? Record the full chain with the end-state tag.
- **Second-order effects:** chained follow-ons (SSRF → metadata creds, XSS → session
  takeover, SSTI → RCE) — walk at least one hop past the first confirmed finding
  before you call the chain done.
- **Detection check (A09:2025):** would the product have *noticed*? Trigger the failed
  login / 403 / exploit request locally and look for it in logs; is anything alerted?
  "Exploited and undetected" is itself a finding.
- **Backdoor impact proof** (03d): only for a confirmed RCE — demonstrate with a
  harmless marker, then check logging/FIM. **Plant nothing.**
- **Cleanup:** remove every artifact you created (temp files, test accounts, uploaded
  PoC files) and **verify removal** — this is part of the deliverable, not an afterthought.

---

## Phase 6 — Kill-chain report & production verdict

Write your verified state back into `findings.json` first (keep the schema, one file),
then:

```bash
node skills/mr-robot/scripts/score.mjs <run-dir>/findings.json
```

This prints the verdict markdown and writes `verdict.json` (CVSS computed from vectors,
severity estimates marked `*`; NO-GO on confirmed criticals/tags like `rce`/`auth-bypass`/`sqli`).
KEV-listed CVEs (merge-time CISA catalog annotation) get their own rationale line —
known-exploited = fix before ship. For pipelines: `score.mjs --ci` gates on the verdict
(exit 0 only on GO) and `scripts/sarif.mjs <run-dir>/findings.json` emits SARIF 2.1.0
for code-scanning upload — both in
[references/07-ci-sarif.md](references/07-ci-sarif.md).

Then write `REPORT.md` following
[references/04-report-template.md](references/04-report-template.md) — **scaffold it
first, then fill it in**:

```bash
node skills/mr-robot/scripts/report.mjs <run-dir>/findings.json -o <run-dir>/REPORT.md
```

`report.mjs` renders every *mechanical* section (findings detail with locations and
status, coverage ledger, rejected list, retest commands, standards crosswalk) and the
verdict line taken from `verdict.json` — it never computes a verdict itself, and never
invents prose: narrative parts come back marked `TODO(agent)`. Fill each marker from
your notebook evidence. Then tell it as an
attacker would: executive summary → verdict + rationale → **the kill chain (how you got
in, step by step, from first probe to final impact)** → findings detail (each with
file:line, source→sink, CWE/CVSS/OWASP, harmless PoC, smallest effective fix) →
coverage ledger (which catalog classes tested/skipped, which scanners failed) →
retest plan.

**Verdict authority:** you may downgrade GO→CONDITIONAL-GO→NO-GO freely when evidence
warrants. Never upgrade past what the evidence supports; if coverage had gaps, the
verdict must say so.

---

## Phase 7 — Remediation & retest (close the loop)

A finding is only closed when a retest proves it. Never declare a fix "done" from
reading the patch alone.

1. **Propose the smallest effective fix** for each confirmed finding — guidance per
   finding family in [references/06-remediation.md](references/06-remediation.md).
   Edit the user's code only with their explicit approval (RoE applies to changes,
   not just tests); never touch anything beyond what the fix needs, and keep the
   scanner's own remediation notes as the source of truth when they exist.
2. **Re-run the same scope against the same target** after the fixes land:

   ```bash
   bash skills/mr-robot/scripts/retest.sh <baseline-run>/findings.json [target-dir] [--live <url> | --passive]
   ```

   It re-runs `scan-all.sh` (same mode as the baseline by default), fingerprints
   every finding (`source_tool` + title + file, normalized for absolute paths and
   line drift), writes `retest.json` next to the new run, and classifies:

   | class | meaning |
   |---|---|
   | `fixed` | absent from the retest **and** its source tool ran ok (or its file is gone from the target) |
   | `persisting` | still present (severity changes are called out) |
   | `unknown` | absent, but its tool was skipped/failed in the retest → **no fix credit** |
   | `new` | not in the baseline — a regression or a previously-unscanned surface |

   Exit codes: `0` everything fixed & nothing new · `1` leftovers (CI-gateable) ·
   `2` usage/run error. Coverage deltas (tools not ok in the retest) are printed
   and recorded — an `unknown` is a coverage gap, not a success.
3. **Fold the evidence back:** mark retest-`fixed` findings `status: "fixed"` in the
   baseline `findings.json` (keep them in the coverage ledger with the retest
   pointer), leave persisting ones untouched, triage `new` findings like any other,
   then re-run `score.mjs` — the verdict may upgrade, but only on this evidence.
4. **Update REPORT.md §7** with the `retest.json` path and the counts. Repeat the
   cycle until retest exits 0 or the user accepts the remaining risk explicitly —
   record the acceptance in the report rather than quieting findings.

---

## File map (progressive disclosure — load on demand)

| File | Load when |
|---|---|
| `references/01-recon.md` | Phase 1 — mapping attack surface from source |
| `references/05-attack-playbook.md` | Phase 2/4 — live enumeration, fuzzing, exploitation tooling & chaining |
| `references/02-toolchain.md` | Phase 3 — tool choice/install questions |
| `references/03a-injection.md` | stack has inputs → SQL/shell/template/HTML/JSON sinks |
| `references/03b-auth-gateway.md` | auth, sessions, RBAC, rate limits exist (or Phase 4) |
| `references/03c-ssrf-access-file.md` | URL-fetching params, file upload/download, path joins |
| `references/03d-supply-chain-backdoors.md` | always (backdoor hunt is passive) |
| `references/03e-business-logic.md` | payments, quotas, workflows, multi-step flows |
| `references/03f-llm-agentic.md` | project calls an LLM/agent/RAG |
| `references/03g-config-crypto-misc.md` | always (config, crypto, logging, error handling) |
| `references/03h-memory-safety.md` | C/C++/Rust/Go unsafe code present |
| `references/03i-http-protocol.md` | proxy/CDN in deploy config, cache layer, Host/reset flows |
| `references/03j-graphql-websocket.md` | GraphQL endpoint or WebSocket/subscription surface |
| `references/03k-oauth-oidc.md` | delegated login (OAuth/OIDC/next-auth/passport) |
| `references/03m-saml-federation.md` | SAML SSO present (assertions, IdP/SP metadata, saml/opensaml deps) |
| `references/03l-traffic-interception.md` | HAR capture to audit, proxy in path, TLS/cookie/token leakage questions |
| `references/03n-known-cves.md` | framework/runtime versions in scope → verify known exploited CVEs (React2Shell, PHP2Shell, middleware bypass) |
| `references/04-report-template.md` | Phase 6 — writing the report |
| `references/06-remediation.md` | Phase 7 — proposing/validating fixes per finding family |
| `references/07-ci-sarif.md` | CI gates, SARIF export, KEV enrichment |
| `references/08-local-daemons.md` | loopback listeners, MCP/dev-tool/DevTools ports, Origin-hijack questions |
| `assets/fixture/` | no target at hand — bundled vulnerable demo app (rehearsal) |

`scripts/setup-tools.sh` · `scripts/scan-all.sh` · `scripts/backdoor-scan.sh` ·
`scripts/race-probe.sh` · `scripts/desync-probe.sh` · `scripts/har-audit.mjs` ·
`scripts/cve-audit.mjs` · `scripts/retest.sh` · `scripts/score.mjs` · `scripts/report.mjs` ·
`scripts/sarif.mjs` · `scripts/selftest.sh` · `scripts/daemon-sweep.sh` ·
`scripts/wordlist-common-passwords.txt` ·
`assets/rules/local.yml` · `assets/gitleaks.toml` · `assets/wordlists/{paths,params}.txt`
