# 07 — CI, SARIF & KEV

How the engagement output plugs into pipelines and dashboards. Everything stays
local: the scripts read `findings.json` and write next to it — no uploads except the
`upload-sarif` step *you* put in *your* workflow.

## SARIF export (code-scanning compatible)

```bash
node skills/mr-robot/scripts/sarif.mjs <run-dir>/findings.json [--out results.sarif]
```

- Emits **SARIF 2.1.0** — one run, one result per finding, `level` from severity
  (critical/high → `error`, medium → `warning`, low/info → `note`).
- **Stable `ruleId`s**: `tool/<well-known-id>` — CVE/GHSA, `CKV_*`, `KSV-*`,
  shellcheck `SC*`, bandit `B*`, gosec `G*`, staticcheck `SA*`, hadolint `DL*`,
  semgrep rule paths, kube-linter check names; fallback `tool/slug(title)`.
  The same finding gets the same ruleId on every run → dashboards group instead of
  duplicating.
- **`partialFingerprints.mrRobotFingerprint`** = sha1(tool|title|file) — survives
  line drift, so a moved-but-unfixed finding stays the same alert.
- Locations are relative to the target dir (`uriBaseId: ROOTPATH`); `properties`
  carry `kev: true` for CISA-KEV-listed CVEs, plus cwe/owasp/status/source_tool.
- Rules carry `security-severity` (worst severity seen for that rule) — what GitHub
  uses to render the severity pill.

### GitHub Actions upload (drop into the target project's workflow)

```yaml
permissions:
  contents: read
  security-events: write     # needed to create code-scanning alerts
steps:
  # ... boot the app locally, run the engagement (Phase 4b), then:
  - name: SARIF export
    run: node skills/mr-robot/scripts/sarif.mjs <run-dir>/findings.json --out mr-robot.sarif
  - name: Upload SARIF
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: mr-robot.sarif
      category: mr-robot          # keeps this run's alerts in their own tab
```

No GitHub? Any SARIF consumer works (GitLab security dashboards, DefectDojo,
SARIF viewers, VS Code extensions) — the file is plain local JSON.

## CI gates (exit codes you can build on)

| Command | Contract |
|---|---|
| `score.mjs <findings> --ci` | `0` GO · `1` CONDITIONAL-GO or NO-GO · `2` usage |
| `retest.sh <baseline> [target]` | `0` all fixed & nothing new · `1` leftovers · `2` error |
| `scan-all.sh` | `0` completed · `2` bad target · `3` refused (non-loopback `--live`) |
| `setup-tools.sh` | always `0` (installs what it can, reports the rest) |

Typical PR gates:

```bash
# quality gate on the current tree (passive — safe in CI, no target needed)
bash skills/mr-robot/scripts/scan-all.sh . > scan.log
node skills/mr-robot/scripts/score.mjs .mr-robot/run-*/findings.json --ci   # fails unless GO
```

```bash
# remediation gate: the build fails until the baseline is fully fixed
bash skills/mr-robot/scripts/retest.sh baseline/findings.json --passive
```

Notes for CI runners: `setup-tools.sh` first (cache `~/.local/bin` +
`~/.cache` between jobs); `MR_ROBOT_NO_NETWORK=1` makes runs hermetic (below);
`--live` still refuses non-loopback hosts, so a CI instance of the app must be
reached via `localhost` inside the job (container/service or `localhost` binding).

## KEV enrichment (CISA Known Exploited Vulnerabilities)

The merge step of `scan-all.sh` annotates CVE findings against the CISA KEV catalog:

- Catalog fetched from `cisa.gov` **once**, cached at
  `~/.cache/mr-robot/kev.json` (7-day TTL) — it is public vulnerability *metadata*,
  like the nuclei template pack: never target data, never your source.
- CVE findings get `kev: true` (in `findings.json`, SARIF `properties.kev`, and
  `verdict.json → kev[]`). `coverage.kev_catalog` records status
  (`fetched` / `cache` / `stale-cache` / `unavailable`) + catalog version.
- `score.mjs` prints a **Known exploited (CISA KEV): N** rationale line — KEV-listed
  vulns are known in-the-wild exploitation: fix before ship regardless of the
  severity bucket. It never *lowers* a verdict.
- Fully offline mode: `MR_ROBOT_NO_NETWORK=1` skips the fetch (a cached catalog is
  still used); if there is no cache, findings simply carry no `kev` field and the
  coverage ledger says `unavailable` — scans never fail over it.

## What CI should never do

- Run `--live` against anything but the job's own localhost instance (enforced
  in code, but the instance is still yours to authorize).
- Auto-fix or auto-`status: confirmed` — verification (Phase 4) and fix approval
  (Phase 7) are human decisions; CI only *gates*, it doesn't *conclude*.
- Commit `findings.json`/`retest.json` with `status` edits — evidence lives in the
  run artifacts (attach `results.sarif` + `verdict.json` to the job).
