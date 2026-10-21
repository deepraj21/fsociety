#!/usr/bin/env node
// mr-robot — HAR audit (references/03l). Zero-dependency, fully offline: the
// HAR you feed it never leaves this machine.
//
// Audits a browser/mitmproxy/curl HTTP Archive (.har) for traffic-level
// issues static analysis and DAST cannot see — what the app actually put on
// the wire: tokens in URLs, credentials over cleartext, cookie flag gaps,
// missing HSTS, over-permissive CORS, passwords in form bodies, stack
// version headers, private-IP disclosure.
//
//   Usage:
//     har-audit.mjs <capture.har>                     → findings-v1 JSON on stdout
//     har-audit.mjs --append <findings.json> <capture.har>
//                                                     → merge into an existing
//                                                       scan-all findings file
//                                                       (ids re-sequenced,
//                                                        counts recomputed)
//
//   Exit: 0 ok · 2 usage/unreadable input
//
// BOUNDS (Phase 0, non-negotiable): read-only over a file you already have;
// no network access, no target contact, no state change. Secrets are REDACTED
// in all evidence (prefix + length only). Severity is a candidate signal —
// verify each hit in context before reporting (skim 03l for the workflow).

import { readFileSync, writeFileSync, existsSync } from "node:fs";

const SEVS = ["critical", "high", "medium", "low", "info"];
const MAX_ENTRIES = 5000; // parse bound — a HAR is just a file, but stay finite
const MAX_FINDINGS = 200; // flood guard
const MAX_BODY_SCAN = 262144; // scan at most 256 KiB of any response body

function die(msg) {
  process.stderr.write(`REFUSED: ${msg}\nusage: har-audit.mjs [--append <findings.json>] <capture.har>\n`);
  process.exit(2);
}

function redact(v) {
  if (v === undefined || v === null || v === "") return "(empty)";
  const s = String(v);
  if (s.length <= 10) return `*** (len ${s.length})`;
  return `${s.slice(0, 6)}…${s.slice(-2)} (len ${s.length})`;
}

const clean = (s) => String(s ?? "").replace(/[\r\n\t]+/g, " ").trim().slice(0, 400);

// ------------------------------------------------------------------ args
const argv = process.argv.slice(2);
let appendPath = null;
let harPath = null;
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === "--append") { appendPath = argv[++i]; if (!appendPath) die("--append needs a findings.json path"); }
  else if (a === "-h" || a === "--help") { process.stdout.write(readFileSync(new URL(import.meta.url), "utf8").split("\n").slice(1, 25).join("\n") + "\n"); process.exit(0); }
  else if (a.startsWith("-")) die(`unknown flag ${a}`);
  else if (harPath) die("exactly one <capture.har> expected");
  else harPath = a;
}
if (!harPath) die("missing <capture.har>");

let har;
try {
  har = JSON.parse(readFileSync(harPath, "utf8"));
} catch (e) { die(`cannot read/parse ${harPath}: ${e.message}`); }
const entries = Array.isArray(har?.log?.entries) ? har.log.entries.slice(0, MAX_ENTRIES) : null;
if (!entries) die(`${harPath} is not a HAR (missing log.entries[] — export "All Traffic" as HAR from DevTools/mitmproxy)`);

// ------------------------------------------------------------------ helpers
const findings = [];
const seen = new Set();
let capped = false;

function emit(rule, severity, title, evidence, extra) {
  const key = `${rule}|${evidence || title}`;
  if (seen.has(key)) return;
  seen.add(key);
  if (findings.length >= MAX_FINDINGS) { capped = true; return; }
  findings.push({
    source_tool: "har-audit",
    title: `${rule}: ${clean(title)}`,
    file: harPath, line: null,
    severity, cwe: extra?.cwe ?? null, owasp: null,
    evidence: evidence ? String(evidence).replace(/[\r\n\t]+/g, " ").slice(0, 600) : null,
    status: "candidate", verified_by: null, notes: null,
    engine: "network",
  });
}

const hdr = (headers, name) =>
  (headers || []).find((h) => String(h?.name || "").toLowerCase() === name.toLowerCase())?.value;

const hostOf = (url) => { try { return new URL(url).host; } catch { return "(unparsed-url)"; } };
const schemeOf = (url) => (String(url).startsWith("https://") ? "https" : String(url).startsWith("http://") ? "http" : "other");
const pathOf = (url) => { try { return new URL(url).pathname; } catch { return "?"; } };

// secret-ish query parameter names + value shape detectors
const SECRET_NAME = /\b(pass(word|wd)?|pwd|secret|token|jwt|api[-_]?key|apikey|auth|access[-_]?token|id[-_]?token|session|sid|sig|signature|private[-_]?key|client[-_]?secret)\b/i;
const JWT_SHAPE = /^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\./;
const LONG_OPAQUE = /^[A-Za-z0-9+/_=-]{24,}$/;
const PRIV_IP = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b/;
const VERSION_HDRS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-runtime", "x-version", "x-generator", "x-drupal-cache"];

// ------------------------------------------------------------------ rules
const hstsHosts = new Set();
let truncatedNote = null;

for (const [idx, entry] of entries.entries()) {
  const req = entry?.request || {};
  const res = entry?.response || {};
  const url = String(req.url || "");
  const host = hostOf(url);
  const scheme = schemeOf(url);
  const path = pathOf(url);
  const method = String(req.method || "GET").toUpperCase();
  const where = `${method} ${path} (${host})`;
  const resHeaders = res.headers || [];

  if (idx === MAX_ENTRIES - 1 && har.log.entries.length > MAX_ENTRIES)
    truncatedNote = `HAR truncated at ${MAX_ENTRIES} entries (had ${har.log.entries.length})`;

  // R1 — secrets/tokens in the query string (leak via logs, history, Referer)
  const qs = (req.queryString || []).length
    ? req.queryString
    : [...new URL(url, "http://x").searchParams].map(([name, value]) => ({ name, value }));
  for (const p of qs) {
    const name = String(p?.name || "");
    const value = String(p?.value || "");
    if (!name || !value) continue;
    if (!SECRET_NAME.test(name) && !JWT_SHAPE.test(value)) continue;
    if (JWT_SHAPE.test(value)) {
      emit("jwt-in-query", "high",
        "JWT in URL query string — leaks via server logs, browser history, Referer headers",
        `${where} — ${name}=${redact(value)}`, { cwe: "CWE-598" });
    } else {
      emit("secret-in-query", "high",
        `secret-looking value in URL query string (param '${clean(name)}') — logs/history/Referer leak`,
        `${where} — ${name}=${redact(value)}`, { cwe: "CWE-598" });
    }
  }

  // R2 — Authorization / Cookie over cleartext http://
  const auth = hdr(req.headers, "Authorization");
  if (scheme === "http" && auth) {
    emit("auth-over-cleartext", "high",
      "Authorization header sent over cleartext http:// — trivially sniffable",
      `${where} — Authorization: ${redact(auth)}`, { cwe: "CWE-319" });
  }
  const cookie = hdr(req.headers, "Cookie");
  if (scheme === "http" && cookie) {
    emit("cookie-over-cleartext", "medium",
      "Cookie sent over cleartext http:// — session material on the wire in the clear",
      `${where} — Cookie: ${redact(cookie)}`, { cwe: "CWE-319" });
  }

  // R3 — response cookie flag gaps (Set-Cookie, first value of each name)
  for (const h of resHeaders || []) {
    if (String(h?.name || "").toLowerCase() !== "set-cookie") continue;
    const first = String(h.value || "").split("\n")[0];
    const cname = (first.split(";")[0] || "").split("=")[0].trim();
    if (!cname) continue;
    const lower = first.toLowerCase();
    if (!/httponly/.test(lower))
      emit("cookie-missing-httponly", "medium",
        `cookie '${clean(cname)}' lacks HttpOnly — readable from JS (XSS pivot)`,
        `${where} — Set-Cookie: ${clean(cname)}=… (${first.split(";").slice(1).map((s) => s.trim()).join("; ") || "no flags"})`, { cwe: "CWE-1004" });
    if (!/secure/.test(lower))
      emit("cookie-missing-secure", "medium",
        `cookie '${clean(cname)}' lacks Secure — will be sent over http://`,
        `${where} — Set-Cookie: ${clean(cname)}=…`, { cwe: "CWE-614" });
    if (!/samesite/.test(lower))
      emit("cookie-missing-samesite", "low",
        `cookie '${clean(cname)}' lacks SameSite — CSRF exposure depends on other controls`,
        `${where} — Set-Cookie: ${clean(cname)}=…`, { cwe: "CWE-352" });
  }

  // R4 — missing HSTS on https responses (once per host)
  if (scheme === "https" && !hstsHosts.has(host) && (res.status || 0) < 400 &&
      !hdr(resHeaders, "Strict-Transport-Security")) {
    hstsHosts.add(host);
    emit("hsts-missing", "low",
      "https host never sends Strict-Transport-Security — first-visit downgrade window",
      `${host} — ${method} ${path} (no HSTS header in capture)`, { cwe: "CWE-319" });
  }

  // R5 — CORS: wildcard (or reflected origin) WITH credentials
  const acao = hdr(resHeaders, "Access-Control-Allow-Origin");
  const acac = hdr(resHeaders, "Access-Control-Allow-Credentials");
  if (acao && String(acac).toLowerCase() === "true") {
    if (acao.trim() === "*") {
      emit("cors-wildcard-credentials", "high",
        "Access-Control-Allow-Origin: * combined with Allow-Credentials: true — browsers reject it, but it signals a broken CORS policy",
        `${where} — ACAO: * + credentials: true`, { cwe: "CWE-942" });
    } else if (acao.startsWith("http")) {
      emit("cors-reflected-credentials", "high",
        "origin-reflecting ACAO with credentials allowed — any site can make authenticated cross-origin reads",
        `${where} — ACAO: ${clean(acao)} + credentials: true`, { cwe: "CWE-942" });
    }
  }

  // R6 — passwords/tokens in urlencoded request bodies
  const pmime = String(req.postData?.mimeType || "");
  if (/application\/x-www-form-urlencoded/i.test(pmime)) {
    const body = String(req.postData?.text || "");
    for (const p of (req.postData?.params?.length ? req.postData.params : [...new URLSearchParams(body)])) {
      const name = String(p?.name || "");
      const value = String(p?.value || "");
      if (!name || !value) continue;
      if (!/pass(word|wd)?|pwd|secret|token|otp/i.test(name)) continue;
      emit("credential-in-body", "high",
        `credential field '${clean(name)}' in urlencoded body — verify TLS on this hop`,
        `${where} — ${name}=${redact(value)}`, { cwe: "CWE-319" });
    }
  }

  // R7 — stack/version disclosure headers
  for (const hn of VERSION_HDRS) {
    const v = hdr(resHeaders, hn);
    if (!v || !/[0-9]/.test(v)) continue;
    emit("version-header", "info",
      `version/stack disclosure in '${hn}' header — narrows attacker's exploit search`,
      `${host} — ${hn}: ${clean(v)}`, { cwe: "CWE-200" });
  }

  // R8 — private-IP disclosure in response bodies (text/json only, capped)
  const rmime = String(res.content?.mimeType || "");
  if (/^(text\/|application\/(json|xml|xhtml))/i.test(rmime)) {
    const body = String(res.content?.text || "").slice(0, MAX_BODY_SCAN);
    const m = PRIV_IP.exec(body);
    if (m && !m[0].startsWith("127.")) {
      emit("private-ip-disclosure", "low",
        "RFC1918/link-local address in response body — internal topology leak",
        `${where} — body contains ${m[0]} (${rmime})`, { cwe: "CWE-200" });
    }
  }
}

// ------------------------------------------------------------------ output
function toDoc(existing) {
  // continue after the existing MAX id — scan-all's own merge dedupes after
  // sequencing, so ids have gaps and count-based numbering would collide
  const maxId = (existing?.findings || []).reduce(
    (m, f) => Math.max(m, parseInt(String(f.id || "").replace(/^MR-/, ""), 10) || 0), 0);
  let n = maxId;
  const renumbered = findings.map((f) => ({ id: `MR-${String(++n).padStart(4, "0")}`, ...f }));
  const all = [...(existing?.findings || []), ...renumbered];
  const counts = Object.fromEntries(SEVS.map((s) => [s, all.filter((f) => f.severity === s).length]));
  const scanners = Array.isArray(existing?.scanners) ? existing.scanners.filter((s) => s.name !== "har-audit") : [];
  scanners.push({
    name: "har-audit",
    status: "ok",
    detail: `${findings.length} finding(s) from ${entries.length} HAR entr${entries.length === 1 ? "y" : "ies"}${truncatedNote ? ` (${truncatedNote})` : ""}`,
  });
  const target = existing?.target ?? "har-capture";
  return {
    schema: "mr-robot-findings-v1",
    target,
    generated_at: new Date().toISOString(),
    mode: existing?.mode ?? "passive",
    coverage: { ...(existing?.coverage || {}), har_audit: { entries: entries.length, truncated: truncatedNote || null } },
    scanners,
    counts,
    findings: all,
  };
}

if (appendPath) {
  let existing = null;
  if (existsSync(appendPath)) {
    try { existing = JSON.parse(readFileSync(appendPath, "utf8")); }
    catch (e) { die(`${appendPath} exists but is not JSON: ${e.message}`); }
    if (existing.schema !== "mr-robot-findings-v1") die(`${appendPath} has schema '${existing.schema}', expected mr-robot-findings-v1`);
  }
  writeFileSync(appendPath, JSON.stringify(toDoc(existing), null, 2) + "\n");
  const total = (existing?.findings?.length || 0) + findings.length;
  process.stderr.write(`[har-audit] ${findings.length} new finding(s) from ${entries.length} entr${entries.length === 1 ? "y" : "ies"} → ${appendPath} (${total} total)\n`);
  for (const s of SEVS) {
    const c = findings.filter((f) => f.severity === s).length;
    if (c) process.stderr.write(`          ${s}: ${c}\n`);
  }
} else {
  process.stdout.write(JSON.stringify(toDoc(null), null, 2) + "\n");
}
if (capped) process.stderr.write(`[har-audit] NOTE: finding cap (${MAX_FINDINGS}) reached — output truncated, narrow the capture\n`);
process.exit(0);
