#!/usr/bin/env node
// mr-robot — findings.json → SARIF 2.1.0 (GitHub code-scanning / any SARIF viewer).
//
//   node sarif.mjs <findings.json> [--out <results.sarif>]
//
// Stable identifiers across runs (so dashboards dedupe properly):
//   - ruleId  = source tool + well-known scanner id when the title carries one
//               (CVE/GHSA/CKV/KSV/SC/B/G/SA/DL, semgrep rule path, k8s check …),
//               else tool + slugified title
//   - partialFingerprints.mrRobotFingerprint = sha1(tool|title|file), line-independent
//
// level: critical/high → error · medium → warning · low/info → note
// kev findings carry properties.kev = true (CISA Known Exploited Vulnerabilities).
// Zero dependencies. Deterministic.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, isAbsolute, sep } from "node:path";
import { createHash } from "node:crypto";

// ---------------------------------------------------------------- CLI
const args = process.argv.slice(2);
let findingsPath = null, outPath = null;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--out") outPath = args[++i];
  else if (!findingsPath) findingsPath = args[i];
}
if (!findingsPath) {
  console.error("usage: sarif.mjs <findings.json> [--out <results.sarif>]");
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
const target = typeof doc.target === "string" ? doc.target : "";

// ---------------------------------------------------------------- helpers
const LEVEL = (sev) =>
  sev === "critical" || sev === "high" ? "error" : sev === "medium" ? "warning" : "note";
const SEV_SCORE = { critical: "9.5", high: "7.5", medium: "5.0", low: "2.5", info: "0.0" };

const slug = (s) =>
  String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 56) || "finding";

// well-known id extraction cascade — first match wins
const RULE_PATTERNS = [
  /^(CVE-\d{4}-\d{4,7})/i,
  /^(GHSA-[\w-]+)/i,
  /\brule (DL\d+)\b/i,                       // hadolint "(rule DL3007)"
  /^\[iac\]\s+(CKV_\w+)/i,                   // checkov
  /^\[misconfig\]\s+([A-Z]+-[\w-]+)/i,      // trivy misconfig (KSV-/DS-/AVD- ids)
  /^(SC\d+):/,                               // shellcheck
  /^(B\d{3}):/,                              // bandit
  /^(G\d{2,3}):/,                            // gosec
  /^(SA\d{4}):/,                             // staticcheck
  /^\[k8s\]\s+([\w-]+):/,                    // kube-linter check name
  /^([a-z0-9_-]+(?:\.[a-z0-9_-]+)+):/,       // semgrep rule path (dotted)
  /^([\w.-]{1,64}):/,                        // generic first token (nuclei templateID, bandit "blacklist:")
];

function ruleIdOf(f) {
  const st = String(f.source_tool || "unknown").toLowerCase();
  const title = String(f.title || "");
  for (const re of RULE_PATTERNS) {
    const m = title.match(re);
    if (m) return `${st}/${m[1]}`;
  }
  return `${st}/${slug(title)}`;
}

const fingerprintOf = (f) =>
  createHash("sha1")
    .update([f.source_tool, f.title, String(f.file ?? "")].join("|"))
    .digest("hex")
    .slice(0, 16);

// file → { uri, startLine } — strips the ":line" suffix some scanners pack in,
// makes paths relative to target when possible (POSIX separators for SARIF)
function locationOf(f) {
  let file = String(f.file ?? "");
  let line = typeof f.line === "number" && f.line > 0 ? f.line : null;
  const m = file.match(/^(.*):(\d+)$/);
  if (m && !isAbsolute(file)) { file = m[1]; line = line ?? Number(m[2]); }
  else if (m && isAbsolute(`${m[1]}`)) {
    // absolute path with packed line (only when the base exists)
    file = m[1]; line = line ?? Number(m[2]);
  }
  if (!file) return null;
  let uri = file;
  if (target && isAbsolute(file)) {
    const rel = relative(target, file);
    if (rel && !rel.startsWith("..") && !isAbsolute(rel)) uri = rel.split(sep).join("/");
  } else {
    uri = file.split(sep).join("/");
  }
  return { uri: uri.replace(/^\.?\//, ""), startLine: line };
}

// ---------------------------------------------------------------- build SARIF
const ruleIndex = new Map(); // ruleId → rule object (first wins)
const rules = [];
const results = [];

for (const f of findings) {
  const rid = ruleIdOf(f);
  const sev = String(f.severity || "info").toLowerCase();
  const level = LEVEL(sev);
  const loc = locationOf(f);

  let rule = ruleIndex.get(rid);
  if (!rule) {
    rule = {
      id: rid,
      name: rid.split("/").pop(),
      shortDescription: { text: String(f.title || rid).slice(0, 300) },
      fullDescription: { text: String(f.title || rid) },
      defaultConfiguration: { level },
      properties: {
        tags: [String(f.source_tool || "unknown"), "mr-robot"],
        "security-severity": SEV_SCORE[sev] ?? "0.0",
      },
    };
    ruleIndex.set(rid, rule);
    rules.push(rule);
  } else if ((SEV_SCORE[sev] ?? 0) > Number(rule.properties["security-severity"] ?? 0)) {
    rule.properties["security-severity"] = SEV_SCORE[sev] ?? "0.0"; // keep worst
  }

  const msg = [f.title, f.evidence ? `Evidence: ${f.evidence}` : null, f.notes ? `Notes: ${f.notes}` : null]
    .filter(Boolean).join("\n");

  const r = {
    ruleId: rid,
    ruleIndex: rules.indexOf(rule),
    level,
    message: { text: msg.slice(0, 2000) },
    partialFingerprints: { mrRobotFingerprint: fingerprintOf(f) },
    properties: {
      id: f.id,
      source_tool: f.source_tool,
      severity: sev,
      status: f.status || "candidate",
      cwe: f.cwe ?? null,
      owasp: f.owasp ?? null,
      engine: f.engine ?? null,
      ...(f.kev === true ? { kev: true } : {}),
    },
  };
  if (loc) {
    r.locations = [{
      physicalLocation: {
        artifactLocation: { uri: loc.uri, uriBaseId: "ROOTPATH" },
        ...(loc.startLine ? { region: { startLine: loc.startLine } } : {}),
      },
    }];
  }
  results.push(r);
}

const kevCov = (doc.coverage && doc.coverage.kev_catalog) || null;
const sarif = {
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  version: "2.1.0",
  runs: [{
    tool: { driver: {
      name: "mr-robot",
      informationUri: "https://github.com/deepraj21/fsociety",
      rules,
    }},
    invocations: [{
      executionSuccessful: true,
      startTimeUtc: doc.generated_at ?? new Date().toISOString(),
      properties: {
        mode: doc.mode ?? "passive",
        target: target,
        kev_catalog: kevCov ? kevCov.status : "unavailable",
      },
    }],
    ...(target ? {
      originalUriBaseIds: { ROOTPATH: {
        description: { text: "engagement target directory" },
        uri: `file://${target}${target.endsWith("/") ? "" : "/"}`,
      }},
    } : {}),
    results,
  }],
};

if (!outPath) outPath = join(dirname(findingsPath), "results.sarif");
writeFileSync(outPath, JSON.stringify(sarif, null, 1));

const byLevel = results.reduce((a, r) => ({ ...a, [r.level]: (a[r.level] ?? 0) + 1 }), {});
const kevN = results.filter((r) => r.properties.kev).length;
console.error(
  `[sarif] ${results.length} result(s) · ${rules.length} rule(s) · ` +
  `error ${byLevel.error ?? 0} / warning ${byLevel.warning ?? 0} / note ${byLevel.note ?? 0}` +
  (kevN ? ` · kev ${kevN}` : "")
);
console.error(`[sarif] written → ${outPath}`);
