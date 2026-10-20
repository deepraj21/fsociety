#!/usr/bin/env node
// mr-robot — findings.json → CVSS scores, severity rollup, production verdict.
//
//   node score.mjs <findings.json> [--out <verdict.json>] [--draft]
//
// --draft: candidate findings not yet verified → verdict is marked "PROVISIONAL".
//
// Verdict rules (production-readiness gate):
//   NO-GO            confirmed critical, or any confirmed tag-blocker
//                    (rce / auth-bypass / authz-bypass / sql-injection / account-takeover)
//   CONDITIONAL-GO   confirmed highs, unverified critical/high candidates, or medium count >= 3
//   GO               everything else (may still carry advisory notes)
//
// Zero dependencies. Deterministic. CVSS v3.1 base-score implementation included.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

// ---------------------------------------------------------------- CLI
const args = process.argv.slice(2);
let findingsPath = null, outPath = null, draft = false;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--out") outPath = args[++i];
  else if (args[i] === "--draft") draft = true;
  else if (!findingsPath) findingsPath = args[i];
}
if (!findingsPath) {
  console.error("usage: score.mjs <findings.json> [--out <verdict.json>] [--draft]");
  process.exit(2);
}

let doc;
try {
  doc = JSON.parse(readFileSync(findingsPath, "utf8"));
} catch (e) {
  console.error(`cannot read findings JSON: ${e.message}`);
  process.exit(2);
}
const findings = Array.isArray(doc.findings) ? doc.findings : [];

// ---------------------------------------------------------------- CVSS v3.1 base
const CVSS_W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  S:  { U: 0, C: 1 },
  C:  { H: 0.56, L: 0.22, N: 0 },
  I:  { H: 0.56, L: 0.22, N: 0 },
  A:  { H: 0.56, L: 0.22, N: 0 },
};
const PR_U = { N: 0.85, L: 0.62, H: 0.27 };
const PR_C = { N: 0.85, L: 0.68, H: 0.5 };

const roundUp1 = (x) => Math.ceil(x * 10) / 10; // CVSS roundup: smallest 1-decimal value >= x

export function cvss31(vector) {
  if (typeof vector !== "string" || !vector.startsWith("CVSS:3.")) return null;
  const parts = Object.fromEntries(
    vector.split("/").slice(1).map((kv) => kv.split(":"))
  );
  const need = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
  for (const k of need) if (!parts[k]) return null;
  try {
    const av = CVSS_W.AV[parts.AV], ac = CVSS_W.AC[parts.AC];
    const pr = (parts.S === "C" ? PR_C : PR_U)[parts.PR];
    const ui = CVSS_W.UI[parts.UI];
    if ([av, ac, pr, ui].some((v) => v === undefined)) return null;
    const exploit = 8.22 * av * ac * pr * ui;

    const c = CVSS_W.C[parts.C], ii = CVSS_W.I[parts.I], a = CVSS_W.A[parts.A];
    if ([c, ii, a].some((v) => v === undefined)) return null;
    const iss = 1 - (1 - c) * (1 - ii) * (1 - a);
    let impact;
    if (parts.S === "C") impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
    else impact = 7.52 * (iss - 0.029) - 0.02 * Math.pow(iss - 0.02, 15);

    let base;
    if (impact <= 0) base = 0;
    else if (parts.S === "C") base = Math.min(1.08 * (impact + exploit), 10);
    else base = Math.min(impact + exploit, 10);
    if (base === 0) return 0;
    return roundUp1(base);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- scoring
const SEV_ESTIMATE = { critical: 9.5, high: 7.5, medium: 5.0, low: 2.5, info: 0.0 };
const BLOCKER_TAGS = new Set([
  "rce", "remote-code-execution", "auth-bypass", "authz-bypass",
  "sql-injection", "account-takeover", "full-takeover", "sqli",
]);

function scoreOf(f) {
  if (typeof f.cvss_score === "number" && Number.isFinite(f.cvss_score)) {
    return { score: f.cvss_score, basis: "reported" };
  }
  if (f.cvss_vector) {
    const s = cvss31(f.cvss_vector);
    if (s !== null) return { score: s, basis: "cvss31-vector" };
  }
  return { score: SEV_ESTIMATE[f.severity] ?? 0, basis: "severity-estimate" };
}

const rows = findings.map((f) => {
  const { score, basis } = scoreOf(f);
  const tags = Array.isArray(f.tags) ? f.tags.map((t) => String(t).toLowerCase()) : [];
  const confirmed = f.status === "confirmed";
  return {
    ...f, cvss_score: score, score_basis: basis, tags, confirmed,
    blocker: confirmed && (f.severity === "critical" || tags.some((t) => BLOCKER_TAGS.has(t))),
  };
});

const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
for (const r of rows) counts[r.severity] = (counts[r.severity] ?? 0) + 1;
const confirmedCounts = rows.filter((r) => r.confirmed)
  .reduce((a, r) => ({ ...a, [r.severity]: (a[r.severity] ?? 0) + 1 }), {});

const blockers = rows.filter((r) => r.blocker);
const unverifiedCriticalHigh = rows.filter(
  (r) => !r.confirmed && (r.severity === "critical" || r.severity === "high")
);
const confirmedHighs = rows.filter((r) => r.confirmed && r.severity === "high");
const mediums = counts.medium ?? 0;

let verdict;
if (blockers.length > 0) verdict = "NO-GO";
else if (confirmedHighs.length > 0 || unverifiedCriticalHigh.length > 0 || mediums >= 3)
  verdict = "CONDITIONAL-GO";
else verdict = "GO";

if (draft || unverifiedCriticalHigh.length > 0) {
  verdict = verdict === "GO" && unverifiedCriticalHigh.length > 0 ? "CONDITIONAL-GO" : verdict;
}

const scanners = Array.isArray(doc.scanners) ? doc.scanners : [];
const failed = scanners.filter((s) => s.status === "failed");
const skipped = scanners.filter((s) => s.status === "skipped");
const coverageNote =
  failed.length || skipped.length
    ? `coverage gaps: ${[...failed, ...skipped].map((s) => `${s.name}(${s.status})`).join(", ")}`
    : "full scanner coverage";

const esc = (v) => (v == null ? "—" : String(v).replace(/\|/g, "\\|"));
const top = [...rows].sort((a, b) => b.cvss_score - a.cvss_score).slice(0, 25);

const md = [
  `# mr-robot production-readiness verdict`,
  ``,
  `- **Verdict:** **${verdict}**${draft ? " *(provisional — verification incomplete)*" : ""}`,
  `- Target: \`${doc.target ?? "?"}\`  •  Mode: ${doc.mode ?? "passive"}  •  Generated: ${doc.generated_at ?? new Date().toISOString()}`,
  `- Findings: **${rows.length}** candidates — critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}, info ${counts.info}`,
  `- Confirmed: ${Object.values(confirmedCounts).reduce((a, b) => a + b, 0)}  •  Blockers: **${blockers.length}**`,
  `- Scanner coverage: ${coverageNote}`,
  ``,
  `## Blockers (force NO-GO)`,
  blockers.length === 0
    ? `_None._`
    : blockers.map((b) => `- **${b.id}** [${b.severity}] ${esc(b.title)} — ${esc(b.file)}${b.line ? ":" + b.line : ""} (${b.cwe ?? "CWE?"})`).join("\n"),
  ``,
  `## Highest-risk findings`,
  ``,
  `| ID | CVSS | Sev | Status | Finding | Location | CWE | OWASP |`,
  `|---|---|---|---|---|---|---|---|`,
  top.map((r) =>
    `| ${r.id} | ${r.cvss_score.toFixed(1)}${r.score_basis === "severity-estimate" ? "*" : ""} | ${r.severity} | ${r.status} | ${esc(r.title)} | ${esc(r.file)}${r.line ? ":" + r.line : ""} | ${r.cwe ?? "—"} | ${r.owasp ?? "—"} |`
  ).join("\n") || "| — | — | — | — | no findings | — | — | — |",
  ``,
  `_* severity-estimate (no CVSS vector reported by the source scanner)`,
  ``,
  `## Verdict rationale`,
  verdict === "NO-GO"
    ? `- ${blockers.length} confirmed blocker(s): any confirmed critical or auth/RCE/SQLi tag fails the production gate.`
    : verdict === "CONDITIONAL-GO"
      ? `- Fix before ship: ${confirmedHighs.length} confirmed high(s), ${unverifiedCriticalHigh.length} critical/high candidate(s) pending verification${mediums >= 3 ? `, ${mediums} mediums (>=3 threshold)` : ""}.`
      : `- No blockers; residual findings are ${counts.medium} medium / ${counts.low} low / ${counts.info} info — track as hardening work.`,
].join("\n");

console.log(md);

if (!outPath) outPath = join(dirname(findingsPath), "verdict.json");
writeFileSync(outPath, JSON.stringify({
  schema: "mr-robot-verdict-v1",
  verdict,
  provisional: Boolean(draft || unverifiedCriticalHigh.length > 0),
  generated_at: new Date().toISOString(),
  counts, confirmed_counts: confirmedCounts,
  blockers: blockers.map((b) => ({ id: b.id, severity: b.severity, title: b.title, file: b.file, line: b.line, cwe: b.cwe })),
  coverage: { failed: failed.map((s) => s.name), skipped: skipped.map((s) => s.name) },
}, null, 2));
console.error(`\n[score] verdict written → ${outPath}`);
