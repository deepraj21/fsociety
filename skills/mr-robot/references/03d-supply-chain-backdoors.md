# 03d — Backdoors, supply chain & integrity (A03/A08/A09:2025)

Two jobs: **find backdoors that exist** (passive), and **prove a backdoor *could* exist
and you'd never know** (active impact proof, gated). The script
`scripts/backdoor-scan.sh` automates the pattern hunt — always run it in Phase 2.

## 1. Backdoor / implant detection (passive — always on)

`backdoor-scan.sh` flags these — **each hit is a candidate; verify in source:**

| Rule ID | What it found | Typical verdict |
|---|---|---|
| REVSHELL-* | bash/python/nc reverse-shell primitives | critical if reachable, else review (could be a legit admin tool) |
| REMOTE-PIPE-EXEC | `curl … \| sh` anywhere in build/runtime | critical in runtime path; review in dev scripts |
| OBFUSC-* | eval(atob…), base64→exec, dense `\u00xx` / fromCharCode chains | almost never legitimate → verify packing |
| HOOK-POSTINSTALL-REMOTE | package hook running curl/nc/chmod | supply-chain implant → critical |
| GIT-HOOK-PLANTED | non-sample file in `.git/hooks/` | critical — inspect content immediately |
| PERSIST-SSH-KEY | private key in tree | critical (rotate) |
| PERSIST-CRON-REBOOT | `@reboot` cron entries in repo | review — could be IaC |
| GIT-DELETED-FILES / GIT-STASH-PRESENT | history signals | info — review diffs for dropped evidence |

Manual complements the script misses:

```bash
# hidden listeners / bind ports in code
grep -rnE "listen\([0-9]{4,5}|bind\(0\.0\.0\.0|socket\(.SOCK_STREAM" --include='*.{py,js,go,c}' .
# rogue admin/debug backdoors
grep -rnE "if *\(.*debug.*=.*true|bypass_auth|skip_auth|secret_admin|magic_key" -i .
# unexpected extra accounts in seeders/fixtures/DB dumps
grep -rniE "insert into users|createuser|is_superuser *= *(true|1)" .
# obfuscated blobs
grep -rnE "['\"][A-Za-z0-9+/]{300,}={0,2}['\"]" --exclude-dir=node_modules .
```

**False-positive discipline:** a reverse-shell primitive in a *test*, a dev bootstrap
script, or an IaC example is still worth reporting as *medium* ("dormant capability:
audit before shipping") — but only `confirmed` if attacker-reachable.

## 2. Supply-chain audit (A03:2025 — highest average exploit/impact of all Top 10)

- **Dependencies:** trivy + osv-scanner output already in findings.json — triage by
  exploitability (fixable version present? reachable?), not raw CVE count.
- **Typosquatting:** diff package names against well-known libs (`lodash` vs `lodahs`,
  `crossenv` vs `cross-env`); check install scripts of obscure deps.
- **Lockfile integrity:** lockfile present + committed? `integrity` hashes present
  (npm `integrity`, pip `--hash`, go sum)? `pip install` without hashes in CI?
- **Install hooks:** `preinstall/postinstall` (npm), `setup.py` `cmdclass`, `*.pth`,
  git `core.hooksPath`, `prepare` scripts — classify every one.
- **CI/CD tampering:** `.github/workflows/*` — `pull_request_target` + checkout of PR code,
  secrets passed to fork PRs, `curl | bash` in workflows, unpinned actions (`@main`),
  script injection via `${{ github.event.* }}` interpolation.
- **Vendored code:** `vendor/`, checked-in minified bundles — diff against upstream?
- **Build integrity:** reproducible builds? signed releases? `verify` steps skipped?

## 3. Integrity failures (A08:2025)

- Deserialization of untrusted data (see 03a), unsigned update mechanisms, JWT/signature
  verification skipped (`verify_signature=False`), `NODE_TLS_REJECT_UNAUTHORIZED=0`,
  cache poisoning defenses, git tag/commit signature policy.

## 4. Logging & alerting gap test (A09:2025) — the "would you even know?" check

An audit-relevant system must log security events **and alert on them**:

- Static: are failed logins, authz denies, admin actions, input-validation failures
  logged? Are secrets/PII masked (`password`, `token` fields logged raw → medium)?
- Dynamic (gated, local): trigger a failed login and a 403 access — is it in the log?
  Then check an *alert* path exists (email/slack/webhook rule, SIEM config). **Logged
  but never alerted = medium finding** ("you'd see it only if you looked").

## 5. Active impact proof for a confirmed RCE — "could a backdoor survive here?"

Only when a `rce`-tagged finding is confirmed AND Phase-0 is satisfied:

1. Demonstrate with the **harmless marker only**: `echo mr-robot-poc` (or a
   `/tmp/mr-robot-poc-*` file you delete immediately).
2. Ask & answer: would this execution have been logged? (check access/app logs for the
   request). Would the *artifact* (new file) have been detected? (no file-integrity
   monitoring → finding "no FIM/detection for executed payloads", medium-high).
3. **Plant nothing.** No cron entries, no hooks, no persistence, no new accounts.
   If your PoC created anything, delete it and **verify deletion** — include the
   verification in the report.
4. Record: attack path, marker evidence, logging verdict → this becomes the report's
   "detected vs undetected" table under the RCE finding.

The deliverable is the *answer to your real question*: **someone could plant a backdoor
here and you would not know** — with the specific gap (no logging / no alert / no FIM)
named so it can be fixed.
