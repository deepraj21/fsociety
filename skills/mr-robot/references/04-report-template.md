# 04 — Report template & verdict rubric

Produce `REPORT.md` (and keep `findings.json` + `verdict.json` beside it). Output
location: `<target>/.mr-robot/report/` unless the user named one. **Never modify target
source** — the report is the deliverable.

## Structure

```markdown
# mr-robot security audit — <project> <date>

## 1. Executive summary
3–6 sentences: what was tested, how, the verdict, the top blockers in plain language.

**VERDICT: GO / CONDITIONAL-GO / NO-GO** (from verdict.json — do not contradict it;
if your judgment differs, adjust findings.json and re-run score.mjs, then explain)

## 2. Scope & method
- Target / commit or version / mode (passive | active)
- Authorization: user-confirmed, localhost-only (Phase 0 record)
- Catalogs exercised: 03a ✓ 03b ✓ 03c ✓ 03d ✓ 03e ✓ 03f ✓ 03g ✓ 03h ✓/–
- Active steps performed (every request you sent, in order) — this is the audit trail

## 3. Attack paths
Ranked chains (source of low findings → end impact). Each: narrative, steps, end tag.

## 4. Findings
For each confirmed finding, in CVSS order:

### <ID> — <title>  [critical/high/… · CVSS x.x · CWE-xxx · Axx:2025]
- **Location:** path:line
- **Source → sink:** input origin … through gates (or lack) … to sink
- **Impact:** what an attacker achieves, in product terms
- **Evidence:** code excerpt + (active) the PoC request/response pair — harmless marker only
- **Fix:** smallest effective change (specific function/config key), plus regression test idea
- **Retest:** exact command/steps to verify the fix

(candidates you rejected: one line each in §6 — not in Findings)

## 5. Coverage ledger
| Catalog class | Status | Notes |
03a…03h rows: tested / skipped-not-applicable / partial (+ why)
| Scanner | Status |
from findings.json → scanners[] (failed/skipped are here — disclose gaps)

## 6. Rejected & needs-validation
ID — reason (not reachable / false positive / needs runtime confirmation).

## 7. Retest plan
Ordered checklist mapping each blocker → verification command.

## 8. Standards crosswalk
OWASP Top 10:2025 · WSTG v4.2 IDs · API Top 10 · LLM/Agentic Top 10 · CWE Top 25 —
which were covered (mirrors §5).
```

## Verdict rubric (mirrors score.mjs — keep them in sync)

| Verdict | Trigger |
|---|---|
| **NO-GO** | ≥1 confirmed critical, **or** any confirmed tag in {rce, auth-bypass, authz-bypass, sql-injection, account-takeover} |
| **CONDITIONAL-GO** | confirmed high(s), or unverified critical/high candidates remain, or ≥3 mediums |
| **GO** | nothing above; residual low/info become hardening backlog |

Rules you may not break:
- Coverage gaps never upgrade the verdict; disclose them in §5.
- Unverified scanner output is never reported as confirmed.
- Downgrade freely on evidence; upgrade only by verifying findings down (not by ignoring).

## Scoring guidance

- Prefer a justified `cvss_vector` (CVSS:3.1 base: AV/AC/PR/UI/S/C/I/A) for confirmed
  findings; `score.mjs` computes the score. Severity-estimates are marked `*` in the table.
- Rank additionally by CWE Top 25 prevalence and exploit-in-the-wild (KEV) — an
  easily-exploited CWE-79 outranks a theoretical high-CVSS edge case in remediation order.
- EPSS/KEV lookups are optional/network; skip unless asked — note when skipped.

## Finding record schema (findings.json — keep stable)

```json
{
  "id": "MR-0001", "source_tool": "semgrep", "title": "...",
  "file": "src/app.py", "line": 42,
  "severity": "high", "cwe": "CWE-89", "owasp": "A05:2025-Injection",
  "evidence": "...", "engine": "sast",
  "status": "candidate | confirmed | rejected",
  "verified_by": "agent", "notes": "source→sink trace",
  "tags": ["sqli"], "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L"
}
```

## Quality bar before you finish

- [ ] score.mjs re-run on final findings.json; verdict.json matches REPORT verdict
- [ ] every confirmed finding has file:line + source→sink + fix
- [ ] every active step appears in §2; every artifact created was removed (verified)
- [ ] coverage ledger honest — failed scanners + skipped catalogs listed
- [ ] target source untouched (`git status` clean apart from `.mr-robot/`)
