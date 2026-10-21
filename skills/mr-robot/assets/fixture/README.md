# ⚠️ DEMO TARGET — intentionally vulnerable

This directory is a **deliberately vulnerable** miniature web app that ships with the
`mr-robot` skill so you can rehearse the full engagement end-to-end before pointing
the skill at your own product.

- **Never deploy it. Never expose it.** It binds `127.0.0.1` only (enforced in code),
  but treat it like any unsafe code: run it in a throwaway directory/VM if unsure.
- **Zero installs.** Python standard library only — no pip, no network, no accounts.

## Boot it

```bash
python3 skills/mr-robot/assets/fixture/app.py      # → http://127.0.0.1:8766
python3 skills/mr-robot/assets/fixture/app.py --tls  # → https://127.0.0.1:8766
                                                     #   (self-signed cert auto-generated
                                                     #    into git-ignored .tls/ — gives
                                                     #    the TLS audit a real target)
```

## Run the full rehearsal (in another terminal, repo root)

```bash
# passive scan of the fixture source
bash skills/mr-robot/scripts/scan-all.sh skills/mr-robot/assets/fixture

# active sweep against the running instance (localhost-only, enforced)
bash skills/mr-robot/scripts/scan-all.sh --live http://127.0.0.1:8766 skills/mr-robot/assets/fixture

# score → verdict, SARIF export
node skills/mr-robot/scripts/score.mjs skills/mr-robot/assets/fixture/.mr-robot/run-*/findings.json --ci
node skills/mr-robot/scripts/sarif.mjs skills/mr-robot/assets/fixture/.mr-robot/run-*/findings.json

# "fix" something in app.py, then prove it:
bash skills/mr-robot/scripts/retest.sh skills/mr-robot/assets/fixture/.mr-robot/run-*/findings.json
```

## What it exercises

| Lane | Where |
|---|---|
| Command injection / eval / weak crypto / pickle / weak RNG | `app.py` |
| Planted (fake) secrets for gitleaks | `app.py` header |
| Dependency CVEs (osv/trivy) | `requirements.txt` (scanned statically; not installed) |
| Dockerfile lint (hadolint + trivy + checkov) | `Dockerfile` |
| Kubernetes misconfig (kube-linter + checkov + trivy) | `k8s/deploy.yaml` |
| Go security + staticcheck (gosec) | `main.go` / `go.mod` |
| Stack fingerprint for tagged nuclei runs | all of the above |
| Live DAST + localhost port sweep | boot `app.py` → `--live` |
| TLS audit (testssl) — self-signed cert, no HSTS | boot `app.py --tls` → `--live https://…` |

`.mr-robot/` (scan outputs) is git-ignored. After your rehearsal, stop the server
with Ctrl-C — nothing persists outside this directory.
