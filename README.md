# fsociety — `mr-robot` agent skill

[![skills.sh](https://skills.sh/b/deepraj21/fsociety)](https://skills.sh/deepraj21/fsociety)

**A full-scope vulnerability hunter and production-readiness auditor that runs as an
agent skill.** It analyzes your whole project with free, local, open-source scanners,
then exploits what it finds through multiple methods — SQL injection, dictionary
attacks, gateway/authz bypass, backdoor detection, prompt injection — proves each with
a harmless proof-of-concept against localhost, and issues a **GO / NO-GO** verdict on
whether the project can ship.

## Install

```bash
npx skills add deepraj21/fsociety --skill mr-robot
```

Browse it on [skills.sh](https://skills.sh/deepraj21/fsociety) once this repo is public.

## Use

Start your coding agent in the project you want audited, then:

```
security audit this project — is it production ready?
```

```
find critical vulnerabilities in this codebase
```

```
hunt for backdoors and test the auth gateway
```

## What it does

| Phase | What happens | Gate |
|---|---|---|
| 0 | Authorization check: target must be the user's own project; active tests localhost-only | hard |
| 1 | Recon: stack, entry points, trust boundaries, gateways, LLM surfaces | passive |
| 2 | Multi-method scan: SAST + secrets + deps + IaC + backdoor heuristics → one `findings.json` | passive |
| 3 | Verify every candidate in source, chain findings into attack paths, tag + score | passive |
| 4 | Active exploitation: credential/dictionary tests, gateway bypass, injection PoCs | **user confirmation** |
| 5 | Report + CVSS + coverage ledger + **GO / CONDITIONAL-GO / NO-GO** | — |

The ~100-test attack catalog is mapped to **OWASP Top 10:2025**, **WSTG**, **OWASP API
Top 10**, **OWASP LLM/Agentic Top 10 2025**, and **MITRE CWE Top 25** — see
[`skills/mr-robot/references/`](skills/mr-robot/references/).

## Zero cost, zero egress

Everything runs on your machine with open-source tools (Opengrep, Trivy, Gitleaks,
OSV-Scanner, Checkov, Bandit, gosec, Nuclei, …). **No accounts, no API keys, no code
ever leaves your machine.** `scripts/setup-tools.sh` installs what's missing and skips
gracefully what it can't.

## Authorization

mr-robot is for auditing **projects you own or are authorized to test**. Passive source
review is always safe; active testing requires your explicit confirmation and is
enforced to localhost in code (`scan-all.sh --live` refuses non-loopback hosts). It
refuses third-party targets, produces non-destructive proof-of-concept demonstrations
only, and plants nothing.

## Layout

```
skills/mr-robot/
├── SKILL.md                 # workflow: phases 0–5
├── references/              # recon, toolchain, 8 attack catalogs, report template
├── scripts/                 # setup-tools.sh · scan-all.sh · backdoor-scan.sh · score.mjs
└── assets/rules/local.yml   # offline fallback SAST rule pack (19 rules)
```

## License

[MIT](LICENSE)
