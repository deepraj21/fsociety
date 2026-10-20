# 02 — Toolchain: free, local, zero-account scanners

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
| IaC / cloud | **Checkov** | Terraform, CFN, K8s, Docker, GH Actions | Apache-2.0 | IaC |
| Python | **Bandit** | Python-specific security smells | Apache-2.0 | Python |
| Go | **gosec** | Go security AST rules | MIT | Go |
| Node | **njsscan** | Node/JS security patterns | LGPL-3.0 | JS/TS |
| Ruby/Rails | **Brakeman** | Rails vulns (free to run on your own code) | Brakeman PUL | Rails |
| Shell | **ShellCheck** | shell script hazards | GPL-3.0 | sh |
| C/C++ | **Cppcheck** | memory/buffer smells | GPL-3.0 | C/C++ |
| DAST (active) | **Nuclei** + community templates | live endpoint vulns | MIT | HTTP targets |
| DAST (active, optional) | **OWASP ZAP** baseline (Docker) | full passive+active crawl | Apache-2.0 | HTTP targets |

## How the orchestrator behaves

```bash
bash scripts/setup-tools.sh            # idempotent installer (non-interactive)
bash scripts/scan-all.sh <dir>         # passive run → <dir>/.mr-robot/run-*/findings.json
bash scripts/scan-all.sh --live http://localhost:3000 <dir>   # + nuclei; loopback enforced
```

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
- `go.mod` → gosec
- `package.json` → njsscan
- `Gemfile` → brakeman
- `*.sh` files → shellcheck
- `*.c/cpp/h` → cppcheck
- IaC present → checkov (+ trivy misconfig)
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
