# 02 — Toolchain: free, local, zero-account scanners & attack tools

Everything mr-robot uses is open-source and runs on the operator's machine. **No
accounts, no API keys, no code egress.** `scripts/setup-tools.sh` installs what it can
and reports the rest — every missing tool becomes a *coverage gap* in the report, never
a crash.

## Matrix

| Layer | Tool | Covers | License | Language reach |
|---|---|---|---|---|
| SAST engine | **Opengrep** (fallback: Semgrep CE) | pattern + taint analysis, cross-file | LGPL-2.1 | 30+ langs |
| SAST offline pack | `assets/rules/local.yml` (19 rules) | SQLi concat, eval/exec, shell=True, pickle, weak hash, verify=False, secrets, privileged containers | ours (MIT) | py/js/yaml/generic |
| Secrets | **Gitleaks** | history + tree, redacted output | MIT | any |
| SCA / CVE | **Trivy** fs | deps CVEs, secrets, misconfig | Apache-2.0 | lockfiles most ecosystems |
| SCA / CVE | **OSV-Scanner** | dependency CVEs (belt & braces) | Apache-2.0 | lockfiles |
| SCA / CVE | `cve-audit.mjs` (built-in) | known-CVE **verification**: fingerprint → curated exploited-CVE table → KEV cache → harmless probe (03n) | ours (MIT) | npm/composer/Docker/PHP |
| IaC / cloud | **Checkov** | Terraform, CFN, K8s, Docker, GH Actions | Apache-2.0 | IaC |
| Python | **Bandit** | Python-specific security smells | Apache-2.0 | Python |
| Go | **gosec** | Go security AST rules | MIT | Go |
| Node | **njsscan** | Node/JS security patterns | LGPL-3.0 | JS/TS |
| Ruby/Rails | **Brakeman** | Rails vulns (free to run on your own code) | Brakeman PUL | Rails |
| Shell | **ShellCheck** | shell script hazards | GPL-3.0 | sh |
| C/C++ | **Cppcheck** | memory/buffer smells | GPL-3.0 | C/C++ |
| Go | **staticcheck** | Go correctness + bug patterns (complements gosec) | MIT | Go |
| Dockerfile | **hadolint** | Dockerfile best-practice & security lint | GPL-3.0 | Dockerfile |
| K8s | **kube-linter** | Kubernetes manifest security checks | Apache-2.0 | K8s YAML |
| JS/TS (opt-in) | **eslint-plugin-security** | object injection, eval, fs-path, timing attacks | MIT | JS/TS |
| DAST (active) | **Nuclei** + community templates (stack-tag filtered) | live endpoint vulns | MIT | HTTP targets |
| DAST (active, optional) | **OWASP ZAP** baseline (Docker) | full passive+active crawl | Apache-2.0 | HTTP targets |
| Recon (active) | **nmap** | localhost port sweep → unexpected listening services | Nmap NPS | TCP ports |

### Active attack toolkit (Phases 2 & 4 — agent-driven, not part of scan-all.sh)

| Tool | Job | Run |
|---|---|---|
| **httpx** | fingerprint what's actually serving (tech, headers, status) | playbook §1 |
| **katana** | JS-aware crawler → URL discovery | playbook §2 |
| **ffuf** | directory/endpoint & parameter brute force | playbook §3–4 |
| **feroxbuster** | recursive content discovery (ffuf complement) | playbook §3 |
| **arjun** | hidden parameter discovery | playbook §4 |
| **sqlmap** | SQLi mechanism proof, bounded (`--level 1 --risk 1 --technique T`) | playbook §6 |
| **jwt_tool** | JWT attacks: alg/key confusion, tampering, `kid` injection | 03b JWT lane |
| **nmap** | bounded localhost port sweep (top-200, in `scan-all.sh --live`) | orchestrator |
| **daemon-sweep.sh** | loopback daemon Origin/CORS hijack sweep (WS forged-Origin handshake) — 08 | any phase (08) |
| **fuzz-lane.mjs** | bounded deterministic mutation fuzzing of local builds + PIE/NX/RELRO/canary checksec — 09 | Phase 4 (09) |

These are run **by you, per endpoint, from
[05-attack-playbook.md](05-attack-playbook.md)** — they need a live target and scope
judgment, so they are not in the orchestrator. Phase 0 rules apply to all of them:
localhost, ≤5 req/s (`-t 5 -rate 5`), bounded wordlists (the bundled
`assets/wordlists/{paths,params}.txt`), marker payloads only.

## How the orchestrator behaves

```bash
bash scripts/setup-tools.sh            # idempotent installer (non-interactive)
bash scripts/scan-all.sh <dir>         # passive run → <dir>/.mr-robot/run-*/findings.json
bash scripts/scan-all.sh --live http://localhost:3000 <dir>   # + nuclei; loopback enforced
```

- **Parallel runs:** independent passive scanners run as background jobs with
  per-scanner logs (`scan.log.<tool>`); `wait_bg_all` collects them before the merge.
  Wall-clock is roughly half of a sequential run on multi-core machines.
- **Stack-aware nuclei:** the live sweep fingerprints the stack (manifests → tags,
  e.g. `python,django,flask,nginx,misconfig,exposure,default-login,cves`) and passes
  it as `-tags` so only relevant templates run — this keeps the 300s watchdog from
  firing on the full community pack. The chosen tag set is recorded in
  `findings.json → coverage.nuclei_template_tags` and the coverage ledger.
- **Rule packs:** tries the online community pack first (downloads *rules only* —
  never your source), falls back to the bundled `assets/rules/local.yml` for fully
  offline runs.
- **Failure handling:** each scanner is validated (JSON must parse). Failures/skips are
  written to `findings.json → scanners[]` and surfaced by `score.mjs` as coverage notes.
- **Exclusions:** `.mr-robot/`, `node_modules/`, `vendor/`, venvs, build dirs are always
  skipped so runs never scan their own output.
- **Exit codes:** scanners returning "findings present" exit codes (0/1) are treated as
  success; only real errors are marked failed.

## Specialist selection rules (run what matches the stack)

- `requirements.txt`/`pyproject.toml` → bandit
- `go.mod` → gosec + staticcheck
- `package.json` → njsscan (+ eslint-plugin-security when already in node_modules)
- `Gemfile` → brakeman
- `*.sh` files → shellcheck
- `*.c/cpp/h` → cppcheck
- IaC present → checkov (+ trivy misconfig)
- Dockerfiles present → hadolint
- k8s manifest dirs (`kubernetes/`, `k8s/`, `deploy/`, `infra/`, `charts/`) → kube-linter
- `--live` mode → nmap localhost sweep (top-200) + stack-tagged nuclei
- always → opengrep/semgrep, gitleaks, trivy, backdoor-scan.sh

## Optional extras (manual, still free)

- `flawfinder` (C/C++), `tfsec` (Terraform), `psalm` (PHP), `staticcheck` (Go),
  `cargo-audit` / `cargo-geiger` (Rust), `trufflehog` (secrets, OSS mode),
  `sqlfluff` no — not security; `kubsec`/`kubesec` (K8s), `checkov` covered.
- ZAP baseline (if Docker available):
  `docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:PORT -r zap.html`
  (run only against the local instance, Phase-0 gate applies).

## Adding a scanner

1. Add an `ensure`/run block in `setup-tools.sh` / `scan-all.sh` following the existing
   pattern (availability check → run → validate JSON → `ran/failrun/skip` note).
2. Add a merger branch in the embedded python of `scan-all.sh` mapping its output to the
   normalized record: `{id, source_tool, title, file, line, severity, cwe, owasp,
   evidence, status:"candidate", engine}`.
3. Keep it free & local — paid/SaaS tools are out of scope for this skill by design.
