#!/usr/bin/env node
// mr-robot — findings.json → REPORT.md skeleton (references/04-report-template.md).
//
//   node report.mjs <findings.json> [-o REPORT.md] [--verdict <verdict.json>]
//
// Renders every section of the report template that is *mechanical* — findings
// detail (location, severity, evidence, status), coverage ledger (scanners[]),
// rejected list, retest plan, standards crosswalk — and leaves explicit
// TODO(agent) markers for what only the engagement agent can write: the
// executive narrative, the kill chain, and the active-step audit trail.
// Nothing here is invented: if the data isn't in findings.json, the report says
// so with a TODO instead of fabricating prose.
//
// The verdict comes from verdict.json (score.mjs output — single source of
// truth). If it's missing, this script tells you to run score.mjs first and
// marks the report PROVISIONAL. report.mjs never computes a verdict itself.
//
//   Exit: 0 ok · 2 usage/unreadable input

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const CATALOGS = [
  ["03a", "injection (SQLi/cmdi/SSTI/XSS/deser/XXE)"], ["03b", "auth & gateway"],
  ["03c", "SSRF / file access"], ["03d", "supply chain & backdoors"],
  ["03e", "business logic"], ["03f", "LLM/agentic"],
  ["03g", "config & crypto"], ["03h", "memory safety"],
  ["03i", "HTTP protocol"], ["03j", "GraphQL/WebSocket"],
  ["03k", "OAuth/OIDC"], ["03l", "traffic interception/HAR"],
  ["03m", "SAML federation"],
];

function die(msg) {
  process.stderr.write(`REFUSED: ${msg}\nusage: report.mjs <findings.json> [-o REPORT.md] [--verdict <verdict.json>]\n`);
  process.exit(2);
}

// ---------------------------------------------------------------- CLI
const args = process.argv.slice(2);
let findingsPath = null, outPath = null, verdictPath = null;
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "-o") { outPath = args[++i]; if (!outPath) die("-o needs a path"); }
  else if (a === "--verdict") { verdictPath = args[++i]; if (!verdictPath) die("--verdict needs a path"); }
  else if (a.startsWith("-")) die(`unknown flag ${a}`);
  else if (findingsPath) die("exactly one <findings.json> expected");
  else findingsPath = a;
}
if (!findingsPath) die("missing <findings.json>");

let doc;
try { doc = JSON.parse(readFileSync(findingsPath, "utf8")); }
catch (e) { die(`cannot read findings JSON: ${e.message}`); }
if (doc.schema !== "mr-robot-findings-v1") die(`unexpected schema '${doc.schema}' (want mr-robot-findings-v1)`);
const findings = Array.isArray(doc.findings) ? doc.findings : [];

let verdict = null;
if (!verdictPath) {
  const guess = join(dirname(findingsPath), "verdict.json");
  verdictPath = existsSync(guess) ? guess : null;
}
if (verdictPath && existsSync(verdictPath)) {
  try { verdict = JSON.parse(readFileSync(verdictPath, "utf8")); }
  catch { verdict = null; }
}

// ---------------------------------------------------------------- helpers
const esc = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ").trim();
const loc = (f) => f.file ? `${f.file}${f.line ? ":" + f.line : ""}` : "—";
const dateStr = (doc.generated_at ? new Date(doc.generated_at) : new Date()).toISOString().slice(0, 10);

const confirmed = findings.filter((f) => f.status === "confirmed");
const rejected = findings.filter((f) => f.status === "rejected");
const candidates = findings.filter((f) => !f.status || f.status === "candidate");
const kevListed = findings.filter((f) => f.kev === true);

const rank = (f) => (f.status === "confirmed" ? 0 : 1) * 10 + SEV_RANK[f.severity] + (f.kev ? -0.5 : 0);
const ordered = [...findings].sort((a, b) => rank(a) - rank(b) || String(a.id).localeCompare(String(b.id)));

const counts = doc.counts ?? Object.fromEntries(
  ["critical", "high", "medium", "low", "info"].map((s) => [s, findings.filter((f) => f.severity === s).length]));
const scanners = Array.isArray(doc.scanners) ? doc.scanners : [];
const gaps = scanners.filter((s) => s.status !== "ok");
const blockers = [...confirmed].filter((f) => f.severity === "critical" ||
  (Array.isArray(f.tags) && f.tags.some((t) => ["rce", "auth-bypass", "authz-bypass", "sql-injection", "account-takeover"].includes(t))));
const active = doc.mode === "active" || doc.coverage?.live_url;

function findingBlock(f) {
  const kevNote = f.kev ? " · **KEV (known-exploited)**" : "";
  const pending = f.status !== "confirmed";
  return [
    `### ${f.id} — ${esc(f.title)}  [${f.severity}${f.cwe ? " · " + f.cwe : ""}${f.owasp ? " · " + esc(f.owasp) : ""}${kevNote}]`,
    `- **Location:** ${esc(loc(f))} · **Source tool:** ${esc(f.source_tool)}${f.engine ? " (" + esc(f.engine) + ")" : ""}`,
    `- **Status:** ${esc(f.status ?? "candidate")}${pending ? " — *pending verification: trace source→sink before reporting as confirmed*" : ""}`,
    f.notes ? `- **Source → sink:** ${esc(f.notes)}` : `- **Source → sink:** _TODO(agent): trace the input through the gates to the sink._`,
    `- **Evidence:** ${esc(f.evidence) || "_TODO(agent): code excerpt / PoC request-response (harmless marker only)._"}`,
    `- **Impact:** _TODO(agent): what an attacker achieves, in product terms._`,
    `- **Fix:** _TODO(agent): smallest effective change — see [06-remediation](06-remediation.md) for this finding family._`,
    `- **Retest:** \`bash skills/mr-robot/scripts/retest.sh ${findingsPath} <target> ${active ? `--live ${doc.coverage?.live_url}` : "--passive"}\` (then confirm this row is \`fixed\`)`,
    "",
  ].join("\n");
}

// ---------------------------------------------------------------- report
const md = [
  `# mr-robot security audit — ${esc(doc.target)} ${dateStr}`,
  ``,
  `> Generated by \`report.mjs\` from \`${findingsPath}\`${verdict ? ` + verdict.json (\`verdict ${verdict.verdict}\`)` : ""}.`,
  `> Mechanical sections are complete; every \`TODO(agent)\` marker must be written`,
  `> by the engagement agent from notebook evidence before this report ships.`,
  verdict ? "" : `> **PROVISIONAL — verdict not computed: run \`score.mjs\` first, then re-run report.mjs.**`,
  ``,
  `## 1. Executive summary`,
  ``,
  verdict
    ? `**VERDICT: ${verdict.verdict}**${verdict.provisional ? " *(provisional — unverified critical/high candidates remain)*" : ""} — from \`verdict.json\` (score.mjs; do not contradict it — adjust findings.json and re-run score.mjs if judgment differs).`
    : `**VERDICT: not computed** — run \`score.mjs\` first.`,
  ``,
  `_TODO(agent): 3–6 sentences — what was tested, how, the verdict in plain language, the top blockers._`,
  ``,
  `${counts.critical} critical · ${counts.high} high · ${counts.medium} medium · ${counts.low} low · ${counts.info} info · ${findings.length} total (${confirmed.length} confirmed, ${candidates.length} pending verification, ${rejected.length} rejected)${kevListed.length ? ` · **${kevListed.length} CISA KEV (known exploited — fix first)**` : ""}.`,
  ``,
  `## 2. Scope & method`,
  ``,
  `- **Target:** \`${esc(doc.target)}\``,
  `- **Mode:** ${esc(doc.mode)}${doc.coverage?.live_url ? ` · live target \`${esc(doc.coverage.live_url)}\`` : ""}`,
  `- **Generated:** ${esc(doc.generated_at ?? dateStr)} · authorization: user-confirmed, localhost-only (Phase 0 record)`,
  `- **Engines:** ${scanners.map((s) => `${esc(s.name)} (${esc(s.status)}${s.detail ? ": " + esc(s.detail) : ""})`).join(", ") || "—"}`,
  kevListed.length ? `- **KEV catalog:** ${esc(doc.coverage?.kev_catalog?.status ?? "annotated")}` : "",
  `- **Active steps performed:** _TODO(agent): every request sent, in order — the audit trail._`,
  ``,
  `## 3. Kill chain & attack paths`,
  ``,
  `_TODO(agent): the engagement narrative — ordered steps from first probe to final impact, each with requests/responses, ranked by end-state end-state impact. Raw material (ordered candidates):_`,
  ``,
  ...(ordered.slice(0, 12).map((f) => `- ${f.id} [${f.severity}] ${esc(f.title)} — ${esc(loc(f))} (${esc(f.source_tool)})`)),
  ``,
  `## 4. Findings`,
  ``,
  ...(confirmed.length
    ? ordered.filter((f) => f.status === "confirmed").map(findingBlock)
    : [`_No confirmed findings yet — ${candidates.length} candidate(s) pending verification (listed below). Confirm or reject each before shipping._`, ``]),
  ...(candidates.length ? [
    `### Pending verification (candidates)`,
    ``,
    ...ordered.filter((f) => f.status !== "confirmed" && f.status !== "rejected").map(findingBlock),
  ] : []),
  `## 5. Coverage ledger`,
  ``,
  `| Catalog class | Status | Notes |`,
  `|---|---|---|`,
  ...CATALOGS.map(([id, name]) => `| ${id} ${name} | _TODO(agent)_ | tested / skipped-not-applicable / partial — with why |`),
  ``,
  `| Scanner | Status | Detail |`,
  `|---|---|---|`,
  ...(scanners.length
    ? scanners.map((s) => `| ${esc(s.name)} | ${esc(s.status)} | ${esc(s.detail) || "—"} |`)
    : [`| — | — | no scanner rows in findings.json |`]),
  ``,
  ...(gaps.length ? [`**Coverage gaps (disclosed, never upgrade the verdict):** ${gaps.map((s) => esc(s.name)).join(", ")}.`, ``] : []),
  `## 6. Rejected & needs-validation`,
  ``,
  ...(rejected.length
    ? rejected.map((f) => `- **${f.id}** — ${esc(f.title)} — rejected: _TODO(agent): reason (not reachable / false positive / needs runtime confirmation)._`)
    : [`_None recorded._`]),
  ``,
  `## 7. Retest plan`,
  ``,
  ...(blockers.length
    ? blockers.map((f) => `- [ ] **${f.id}** [${f.severity}] ${esc(f.title)} — fix lands → run the retest: \`bash skills/mr-robot/scripts/retest.sh ${findingsPath} <target> ${active ? `--live ${doc.coverage?.live_url}` : "--passive"}\``)
    : [`_No confirmed blockers. After fixes: \`bash skills/mr-robot/scripts/retest.sh ${findingsPath} <target> ${active ? `--live ${doc.coverage?.live_url}` : "--passive"}\` — record \`retest.json\` counts (fixed/persisting/unknown/new) here._`]),
  ``,
  `A finding's row above gets \`status: fixed\` only with retest evidence.`,
  ``,
  `## 8. Standards crosswalk`,
  ``,
  `- **OWASP Top 10:2025** · **WSTG v4.2** · **OWASP API Top 10:2023** · **LLM/Agentic Top 10** · **CWE Top 25** — coverage mirrors §5.`,
  `- Distinct CWEs observed: ${[...new Set(findings.map((f) => f.cwe).filter(Boolean))].sort().join(", ") || "none tagged"}.`,
  `- KEV (known exploited in the wild): ${kevListed.length ? kevListed.map((f) => `${f.id} (${f.cwe ?? "cwe?"})`).join(", ") : "none"}.`,
  ``,
  `---`,
  `_Report structure follows references/04-report-template.md · verdict from score.mjs (verdict.json) · scores/CVSS from score.mjs output._`,
  ``,
].filter((l) => l !== null).join("\n");

if (outPath) {
  writeFileSync(outPath, md);
  const todos = (md.match(/TODO\(agent\)/g) || []).length;
  process.stderr.write(`[report] wrote ${outPath} — ${findings.length} findings, ${todos} TODO(agent) marker(s) to fill\n`);
} else {
  process.stdout.write(md);
}
process.exit(0);
