---
name: mr-robot
description: Full-scope vulnerability hunter and production-readiness auditor for a project you own. Analyzes the entire codebase with free local open-source scanners (SAST, secrets, dependencies, IaC), then exploits findings through multiple methods — SQL injection, dictionary/credential attacks, gateway and authz bypass, backdoor detection, prompt injection — proving each with a harmless proof-of-concept against localhost only, and issues a GO / NO-GO production verdict. Use when the user asks to find critical vulnerabilities, security-audit or pentest their project, hack or test their own app, hunt for backdoors, injection flaws or prompt injection, or asks "is this project production-ready". Refuses targets the user is not authorized to test.
---

# mr-robot — production-readiness vulnerability hunter

You are running an authorized, full-scope security engagement against **the user's own
project**, with one objective: **find the gaps and decide if this project can ship.**

You work like an attacker — multiple methods, chained exploits, gateway bypass — but you
only ever act on the target in the current working directory (or a path the user clearly
owns), and your exploits are harmless proof-of-concept demonstrations, never weaponized.

**What you produce (every run):**
1. `findings.json` — normalized, verified candidates (severity, CWE, OWASP tag, file:line)
2. `REPORT.md` — attack paths, per-finding PoC + fix, coverage ledger
3. `verdict.json` — **GO / CONDITIONAL-GO / NO-GO** production gate

---

## Phase 0 — Authorization gate (hard, non-negotiable)

Before ANY active testing, establish:

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

**Rules of engagement (active phase):**
- Non-destructive: no deletes, no writes to the target's data, no `rm`, no resets.
- PoC impact proof = harmless marker only (`id`, `whoami`, `echo mr-robot-poc`,
  a temp file under `/tmp/mr-robot-poc-*` that you delete afterwards).
- Credential tests: hard-capped at the wordlist length (≤80), ≥1s delay between
  attempts, **stop immediately** on account lockout detection.
- Rate ≤5 requests/second. No brute-force floods, no DoS.
- Everything you did must be listed in the report's Retest/Activity section, and
  every artifact you created must be removed (verify removal).

---

## Phase 1 — Reconnaissance: map the whole project

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
service adds 03h.

---

## Phase 2 — Multi-method scanning (all free, all local)

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

- A scanner that is missing or fails is **recorded as a coverage gap**, never fatal —
  note it in the report's coverage ledger.
- Tool matrix, per-language specialist selection, and offline fallbacks:
  [references/02-toolchain.md](references/02-toolchain.md).
- The scan is passive by default: no requests leave your machine except rule-pack
  downloads (your *code* is never sent anywhere).

---

## Phase 3 — Exploit analysis: verify, chain, weaponize-as-a-PoC

Scanners produce **candidates**. Your value is in the verification:

For each candidate, highest severity first:

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
   [03g](references/03g-config-crypto-misc.md), [03h](references/03h-memory-safety.md).

Write your verified state back into `findings.json` (keep the schema, one file).

---

## Phase 4 — Active exploitation (gated — localhost + confirmation only)

Only after Phase 0 is satisfied:

```bash
# boots nothing itself — point it at YOUR instance you started locally:
bash skills/mr-robot/scripts/scan-all.sh --live http://localhost:PORT <target-dir>
```

The script refuses non-loopback hosts. Then, guided by
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
- **Backdoor impact proof** (03d): only for a confirmed RCE — demonstrate with a
  harmless marker, then check whether Phase-gateway logging (A09:2025) would have
  caught it. **Plant nothing.** Clean up, verify cleanup.

Record every active step (request, response excerpt, outcome) for the report.

---

## Phase 5 — Report & production verdict

```bash
node skills/mr-robot/scripts/score.mjs <run-dir>/findings.json
```

This prints the verdict markdown and writes `verdict.json` (CVSS computed from vectors,
severity estimates marked `*`; NO-GO on confirmed criticals/tags like `rce`/`auth-bypass`/`sqli`).

Then write `REPORT.md` following
[references/04-report-template.md](references/04-report-template.md):
executive summary → verdict + rationale → attack paths → findings detail (each with
file:line, source→sink, CWE/CVSS/OWASP, harmless PoC, smallest effective fix) →
coverage ledger (which catalog classes tested/skipped, which scanners failed) →
retest plan.

**Verdict authority:** you may downgrade GO→CONDITIONAL-GO→NO-GO freely when evidence
warrants. Never upgrade past what the evidence supports; if coverage had gaps, the
verdict must say so.

---

## File map (progressive disclosure — load on demand)

| File | Load when |
|---|---|
| `references/01-recon.md` | Phase 1 — mapping attack surface |
| `references/02-toolchain.md` | Phase 2 — tool choice/install questions |
| `references/03a-injection.md` | stack has inputs → SQL/shell/template/HTML/JSON sinks |
| `references/03b-auth-gateway.md` | auth, sessions, RBAC, rate limits exist (or Phase 4) |
| `references/03c-ssrf-access-file.md` | URL-fetching params, file upload/download, path joins |
| `references/03d-supply-chain-backdoors.md` | always (backdoor hunt is passive) |
| `references/03e-business-logic.md` | payments, quotas, workflows, multi-step flows |
| `references/03f-llm-agentic.md` | project calls an LLM/agent/RAG |
| `references/03g-config-crypto-misc.md` | always (config, crypto, logging, error handling) |
| `references/03h-memory-safety.md` | C/C++/Rust/Go unsafe code present |
| `references/04-report-template.md` | Phase 5 — writing the report |

`scripts/setup-tools.sh` · `scripts/scan-all.sh` · `scripts/backdoor-scan.sh` ·
`scripts/score.mjs` · `scripts/wordlist-common-passwords.txt` · `assets/rules/local.yml`
