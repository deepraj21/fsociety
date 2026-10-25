# fsociety — `mr-robot` agent skill

[![skills.sh](https://skills.sh/b/deepraj21/fsociety)](https://skills.sh/deepraj21/fsociety)

**A real penetration-testing experience for your product, run by your agent.**
`mr-robot` takes an app you own through a full red-team engagement — recon → live
endpoint enumeration & fuzzing → vulnerability hunting → exploitation →
post-exploitation impact proof — using only free, local, open-source tooling, then
hands back a kill-chain report and a **GO / NO-GO** verdict on shipping. When you
fix, it closes the loop: `scripts/retest.sh` re-runs the same scope and proves each
finding `fixed` / `persisting` / `new` — no fix claimed without evidence. Results
export as **SARIF 2.1.0** (`scripts/sarif.mjs`) for code-scanning dashboards, CVE
findings are annotated against the **CISA KEV** catalog (cached, offline-safe), and
`score.mjs --ci` / `retest.sh` exit codes gate pipelines.

```
/mr-robot take down my product
```

## Install

```bash
npx skills add deepraj21/fsociety --skill mr-robot
```

Then, with your coding agent started **inside the project you want attacked**:

## Use

```
/mr-robot take down my product
```

```
/mr-robot pentest this API
```

```
/mr-robot hack this app — find the way in
```

```
/mr-robot red-team the auth flow and prove the impact
```

It also triggers on plain language: *"find critical vulnerabilities in this codebase"*,
*"hunt for backdoors / prompt injection"*, *"is this production ready?"*.

## Demo target (practice safely)

No target yet? The skill ships an **intentionally vulnerable** fixture you can boot
locally — Python stdlib only, zero installs, binds `127.0.0.1:8766`:

```bash
python3 skills/mr-robot/assets/fixture/app.py
# then, in another terminal — full rehearsal: scan → --live → verdict → fix → retest
bash skills/mr-robot/scripts/scan-all.sh --live http://127.0.0.1:8766 skills/mr-robot/assets/fixture
```

It plants the classic lanes — command/SQL/code injection, path traversal, weak
crypto, pickle, fake secrets, vulnerable deps, insecure Dockerfile/k8s manifests,
Go security bugs — so every scanner in the toolchain has something real to find.

## The engagement

| Phase | What happens | Gate |
|---|---|---|
| 0 | Rules of engagement: target must be your project; live tests localhost-only | hard |
| 1 | Recon: stack, entry points, trust boundaries, gateways, LLM surfaces — attacker hypotheses seeded | passive |
| 2 | Enumeration: fingerprint, crawl, directory/param brute (ffuf, feroxbuster, katana, arjun), JS-mined endpoints → live attack-surface diff | **user confirmation** |
| 3 | Hunting: SAST + secrets + deps + IaC + backdoor scan → candidates in one `findings.json` | passive |
| 4 | Exploitation: verify every candidate in source, chain into attack paths, then live PoCs (nuclei, sqlmap, bounded credential tests, gateway bypass) | **user confirmation** |
| 5 | Post-exploitation: blast radius, privilege paths, detection check (A09), cleanup + verified removal | **user confirmation** |
| 6 | Kill-chain report + CVSS + coverage ledger + **GO / CONDITIONAL-GO / NO-GO** | — |

The ~120-test attack catalog is mapped to **OWASP Top 10:2025**, **WSTG**, **OWASP API
Top 10**, **OWASP LLM/Agentic Top 10 2025**, and **MITRE CWE Top 25** — covering
injection (SQLi, SSTI, XSS, XXE, deserialization), auth/gateway bypass, SSRF, file
access, supply-chain backdoors, business logic & races, LLM/agentic abuse, config/crypto,
memory safety, HTTP protocol attacks (smuggling, cache poisoning, ReDoS),
GraphQL/WebSocket, and OAuth/OIDC — see
[`skills/mr-robot/references/`](skills/mr-robot/references/), especially
[`05-attack-playbook.md`](skills/mr-robot/references/05-attack-playbook.md) for the
enumeration → exploit → chain workflow.

## How it works (vs. a scanner)

A scanner reports isolated findings. `mr-robot` runs the loop professional pentest
tools and AI pentest agents use: build a mental model of the target → enumerate the
*live* surface → probe systematically → verify each lead in source → **chain** low
findings into kill chains ("leaked internal URL + SSRF = admin takeover") → prove each
with a harmless marker payload → write the engagement up as a story of how the product
would go down. Every rejected lead stays in the notebook; every claimed test appears in
the coverage ledger.

## Zero cost, zero egress

Everything runs on your machine with open-source tools (ffuf, feroxbuster, httpx,
katana, arjun, nuclei, sqlmap, nmap, testssl, mitmproxy, Opengrep, Trivy, Gitleaks,
Bandit, gosec, staticcheck, hadolint, kube-linter, jwt_tool, …). **No
accounts, no API keys, no code ever leaves your machine.** `scripts/setup-tools.sh`
installs what's missing and skips gracefully what it can't.

## Authorization

mr-robot is for penetration testing **projects you own or are authorized to test** —
same rules of engagement as a professional pentest: passive source review is always
allowed, active testing requires your explicit confirmation and is enforced to localhost
in code (`scan-all.sh --live` refuses non-loopback hosts). It refuses third-party
targets, uses non-destructive proof-of-concept markers only, never plants persistence,
and always cleans up after itself. Traffic interception is loopback-only and
capture-first (audit your own HAR exports, or proxy a localhost app) — **LAN MITM
(ARP spoofing, SSL stripping, sniffing third-party traffic) is out of scope.**

## Layout

```
skills/mr-robot/
├── SKILL.md                 # engagement workflow: phases 0–6
├── references/              # recon, toolchain, attack playbook, 13 catalogs, report template
├── scripts/                 # setup-tools.sh · scan-all.sh · backdoor-scan.sh · race-probe.sh · desync-probe.sh · har-audit.mjs · retest.sh · score.mjs · report.mjs · sarif.mjs · selftest.sh
└── assets/                  # offline SAST rule pack, gitleaks config, path/param wordlists
```

## License

[MIT](LICENSE)
