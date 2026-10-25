#!/usr/bin/env node
// romero — capture.json → REPORT.md (the complete browser picture).
//
//   node report.mjs <capture.json> [-o REPORT.md]
//
// Renders 12 sections from one capture: summary · pages/frames · API surface
// (grouped endpoint templates + GraphQL + WS/SSE) · request-header inventory ·
// response headers + security-header checklist · cookies · storage dump ·
// tokens & credentials found in traffic (JWTs decoded locally) · third-party
// contacts and what data they receive · performance/caching/protocol ·
// console/errors/security log · observations + coverage gaps.
//
// Values are rendered RAW — the report is a local artifact for the operator
// (the capture never left the machine; nothing is masked). Section 12 is
// advisory only: romero issues NO verdict — production-readiness calls belong
// to mr-robot's score.mjs.
//
// Exit: 0 ok · 2 usage/unreadable input.

import { existsSync, readFileSync, writeFileSync } from "node:fs";

function die(msg) {
  process.stderr.write(`REFUSED: ${msg}\nusage: report.mjs <capture.json> [-o REPORT.md]\n`);
  process.exit(2);
}

// ---------------------------------------------------------------- CLI
const args = process.argv.slice(2);
let inPath = null, outPath = null;
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "-o") { outPath = args[++i]; if (!outPath) die("-o needs a path"); }
  else if (a.startsWith("-")) die(`unknown flag ${a}`);
  else if (inPath) die("exactly one <capture.json> expected");
  else inPath = a;
}
if (!inPath) die("missing <capture.json>");
if (!existsSync(inPath)) die(`not found: ${inPath}`);

let cap;
try { cap = JSON.parse(readFileSync(inPath, "utf8")); }
catch (e) { die(`cannot read capture JSON: ${e.message}`); }
if (cap.schema !== "mr-romero-capture-v1") die(`unexpected schema '${cap.schema}' (want mr-romero-capture-v1)`);
const reqs = Array.isArray(cap.requests) ? cap.requests : [];

// ---------------------------------------------------------------- helpers
const esc = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ").trim();
const short = (s, n = 160) => { s = String(s ?? ""); return s.length > n ? s.slice(0, n) + `…(${s.length} chars)` : s; };
const urlOf = (u) => { try { return new URL(u); } catch { return null; } };
const hostOf = (u) => urlOf(u)?.host ?? "(invalid-url)";
const schemeOf = (u) => urlOf(u)?.protocol ?? "?";

let entryHost = "";
try { entryHost = new URL(cap.target).host; } catch { entryHost = hostOf(cap.target); }
const isSame = (u) => hostOf(u) === entryHost;

const phaseTs = cap.phaseStart ? Date.parse(cap.phaseStart) : NaN;
const reqTs = (r) => (r.wallTime ? r.wallTime * 1000 : Date.parse(r.startedAt || cap.startedAt));
const prePhase = phaseTs ? reqs.filter((r) => reqTs(r) < phaseTs).length : 0;

const respHeadersOf = (r) => ({
  ...(r.response?.headers || {}),
  ...(r.redirect?.headers || {}),
  ...(r.extraHeaders || {}),
});
const statuses = (r) => r.response?.status ?? r.redirect?.status ?? null;

function pathTemplate(pathname) {
  return pathname.split("/").map((seg) => {
    if (!seg) return seg;
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) return ":uuid";
    if (/^\d+$/.test(seg)) return ":id";
    if (/^[0-9a-f]{16,}$/i.test(seg)) return ":hex";
    if (/^[A-Za-z0-9_-]{24,}$/.test(seg) && /\d/.test(seg)) return ":opaque";
    if (/\.[a-z0-9]{2,5}$/i.test(seg) && seg.length < 40) return seg; // file names stay
    if (seg.length > 28) return ":id";
    return seg;
  }).join("/");
}

function postDataFields(r) {
  if (!r.postData) return { fields: [], kind: null, graphql: null };
  const ct = String(Object.entries(r.headers || {}).find(([k]) => k.toLowerCase() === "content-type")?.[1] || "");
  // GraphQL?
  try {
    const j = JSON.parse(r.postData);
    if (j && (j.query || j.operationName)) {
      const m = typeof j.query === "string" ? j.query.match(/^\s*(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)?/) : null;
      return { fields: j.query && !j.operationName && m ? [m[2] || m[1]] : Object.keys(j), kind: "graphql",
               graphql: { operation: j.operationName || (m ? `${m[1]}${m[2] ? " " + m[2] : ""}` : "query"), query: short(j.query, 300) } };
    }
    if (j && typeof j === "object") return { fields: Object.keys(j), kind: "json", graphql: null };
  } catch { /* not JSON */ }
  if (/x-www-form-urlencoded/.test(ct) || /^[^=&\s]+=[^&]*(&[^=&\s]+=[^&]*)*$/.test(r.postData)) {
    return { fields: [...r.postData.matchAll(/(?:^|&)([^=&\s]+)=/g)].map((m) => m[1]), kind: "form", graphql: null };
  }
  return { fields: [], kind: /text/.test(ct) ? "text" : "raw", graphql: null };
}

const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g;
function decodeJwt(tok) {
  try {
    const p = JSON.parse(Buffer.from(tok.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    const out = {};
    for (const k of ["iss", "sub", "aud", "exp", "iat", "nbf", "scope", "roles", "role", "admin", "name", "email", "preferred_username"]) {
      if (k in p) out[k] = k === "exp" || k === "iat" || k === "nbf" ? `${p[k]} (${new Date(p[k] * 1000).toISOString()})` : p[k];
    }
    const extra = Object.keys(p).filter((k) => !(k in out) && k !== "jti" && k !== "nonce");
    if (extra.length) out._other = extra.join(", ");
    return out;
  } catch { return null; }
}
const SECRET_PATTERNS = [
  ["AWS access key", /\bAKIA[0-9A-Z]{16}\b/g],
  ["GitHub token", /\b(?:gho|ghp|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b/g],
  ["Slack token", /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g],
  ["OpenAI-style key", /\bsk-[A-Za-z0-9_-]{20,}\b/g],
  ["Bearer credential", /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}/g],
  ["Basic credential", /\bBasic\s+[A-Za-z0-9+/]{16,}={0,2}\b/g],
];

// ---------------------------------------------------------------- collect
const sameReqs = reqs.filter((r) => isSame(r.url));
const thirdReqs = reqs.filter((r) => !isSame(r.url));

// §3 API surface (same-origin)
const groups = new Map();
for (const r of sameReqs) {
  const u = urlOf(r.url); if (!u) continue;
  const key = `${r.method} ${u.host}${pathTemplate(u.pathname)}`;
  if (!groups.has(key)) groups.set(key, { method: r.method, tmpl: pathTemplate(u.pathname), n: 0, statuses: new Set(), types: new Set(), queries: new Set(), post: null, authHdr: null, ws: false, times: [] });
  const g = groups.get(key);
  g.n++;
  const s = statuses(r); if (s) g.statuses.add(s);
  g.types.add(r.type);
  for (const k of u.searchParams.keys()) g.queries.add(k);
  const authK = Object.entries(r.headers || {}).find(([k]) => /^(authorization|x-api-key|api-key)$/i.test(k));
  if (authK) g.authHdr = `${authK[0]}: ${short(authK[1], 60)}`;
  if (r.postData) {
    const pf = postDataFields(r);
    g.post = { kind: pf.kind, fields: [...new Set([...(g.post?.fields || []), ...pf.fields])], graphql: pf.graphql || g.post?.graphql || null };
  }
  if (r.finished?.durationMs) g.times.push(r.finished.durationMs);
}

// §4/§5 header inventories
function headerInventory(rows) {
  const freq = new Map();
  for (const r of rows) {
    const h = respHeadersOf(r);
    for (const [k, v] of Object.entries(h)) {
      const e = freq.get(k) || { n: 0, example: v };
      e.n++; if (String(v).length > String(e.example).length) e.example = v;
      freq.set(k, e);
    }
  }
  return freq;
}
function requestHeaderInventory(rows) {
  const freq = new Map();
  for (const r of rows) {
    for (const [k, v] of Object.entries(r.headers || {})) {
      const e = freq.get(k) || { n: 0, example: v };
      e.n++; freq.set(k, e);
    }
    for (const [k, v] of Object.entries(r.reqExtraHeaders || {})) {
      if (!freq.has(k)) freq.set(k, { n: 0, example: v, extraOnly: true });
    }
  }
  return freq;
}

// §5 security checklist — evaluated on same-origin responses that carry status
const checklistDefs = [
  ["Content-Security-Policy", /content-security-policy/i, "policy blocks injected scripts"],
  ["Strict-Transport-Security", /strict-transport-security/i, "HTTPS-only pinning (https targets only)"],
  ["X-Frame-Options", /x-frame-options/i, "clickjacking (or CSP frame-ancestors)"],
  ["X-Content-Type-Options", /x-content-type-options/i, "MIME sniffing"],
  ["Referrer-Policy", /referrer-policy/i, "referrer leakage control"],
  ["Permissions-Policy", /permissions-policy|feature-policy/i, "powerful-feature gating"],
  ["Cross-Origin-Opener-Policy", /cross-origin-opener-policy/i, "window-isolation"],
  ["Cross-Origin-Resource-Policy", /cross-origin-resource-policy/i, "resource hotlinking"],
  ["Cross-Origin-Embedder-Policy", /cross-origin-embedder-policy/i, "document isolation"],
];

// §6 cookies
const jar = cap.cookies?.post || [];
const setEvents = [];
for (const r of reqs) {
  const h = respHeadersOf(r);
  for (const [k, v] of Object.entries(h)) {
    if (k.toLowerCase() !== "set-cookie") continue;
    for (const line of String(v).split("\n")) {
      const [first, ...attrs] = line.split(";");
      const [name, ...val] = first.split("=");
      const flags = attrs.map((a) => a.trim().split("=")[0].toLowerCase());
      setEvents.push({ name: name.trim(), value: val.join("=").trim(), url: r.url, flags, raw: short(line, 200) });
    }
  }
}

// §7 storage (last harvest per origin wins — capture already deduped)
const storage = cap.storage || [];

// §8 tokens & credentials
const tokens = [];
const addToken = (where, kind, detail, value) => tokens.push({ where, kind, detail, value: short(value, 600) });
for (const r of sameReqs.concat(thirdReqs)) {
  for (const [k, v] of Object.entries(r.headers || {})) {
    if (/^authorization$/i.test(k)) addToken(r.url, "request header", k, v);
    if (/^(x-api-key|api-key|x-auth-token|x-access-token)$/i.test(k)) addToken(r.url, "request header", k, v);
  }
  const u = urlOf(r.url);
  if (u) for (const [k, v] of u.searchParams) {
    if (/pass|pwd|secret|token|jwt|api[-_]?key|session|auth|sig/i.test(k) && v) addToken(r.url, "URL query", k, v);
  }
  if (r.postData) {
    const pf = postDataFields(r);
    for (const f of pf.fields) if (/pass|pwd|secret|token|otp|key/i.test(f)) {
      const m = r.postData.match(new RegExp(`(?:^|&)${f.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}=([^&]*)`));
      addToken(r.url, "request body", `${f} (${pf.kind})`, m ? decodeURIComponent(m[1]) : r.postData);
    }
  }
  // cookies carrying JWTs
  const ck = Object.entries(r.headers || {}).find(([k]) => k.toLowerCase() === "cookie");
  if (ck) for (const part of String(ck[1]).split(";")) {
    const [n, ...v] = part.trim().split("="); const val = v.join("=");
    if (JWT_RE.test(val)) { JWT_RE.lastIndex = 0; addToken(r.url, "cookie", n.trim(), val); } else JWT_RE.lastIndex = 0;
  }
}
for (const s of storage) {
  for (const [k, v] of Object.entries({ ...s.localStorage, ...s.sessionStorage })) {
    if (/pass|secret|token|jwt|key|session|auth|cred/i.test(k)) addToken(s.origin, "browser storage", k, v);
    else if (String(v).startsWith("eyJ")) addToken(s.origin, "browser storage", k, v);
  }
}
const jwts = new Map(); // token → [where...]
for (const t of tokens) for (const m of String(t.value).matchAll(JWT_RE)) {
  const tok = m[0]; if (!jwts.has(tok)) jwts.set(tok, []); jwts.get(tok).push(`${t.where} (${t.detail})`);
}
for (const [tok, where] of jwts) tokens.push({ where: where.join(" · "), kind: "JWT", detail: JSON.stringify(decodeJwt(tok) || "(undecodable)"), value: tok });
// generic secret-pattern sweep over request material
for (const r of reqs) {
  const hay = [JSON.stringify(r.headers || {}), r.postData || "", r.url].join("\n");
  for (const [name, re] of SECRET_PATTERNS) {
    re.lastIndex = 0;
    const m = hay.match(re);
    if (m && !/^\[?romero/.test(m[0])) addToken(r.url, "pattern match", name, m[0]);
  }
}

// §9 third parties
const third = new Map();
for (const r of thirdReqs) {
  const u = urlOf(r.url); if (!u) continue;
  const e = third.get(u.host) || { host: u.host, n: 0, types: new Set(), params: new Set(), post: new Set(), cookiesSent: false, initiator: new Set(), schemes: new Set(), statuses: new Set() };
  e.n++;
  e.types.add(r.type);
  e.schemes.add(u.protocol.replace(":", ""));
  const s = statuses(r); if (s) e.statuses.add(s);
  for (const k of u.searchParams.keys()) e.params.add(k);
  if (r.postData) for (const f of postDataFields(r).fields) e.post.add(f);
  if (Object.keys(r.headers || {}).some((k) => k.toLowerCase() === "cookie") || Object.keys(r.reqExtraHeaders || {}).some((k) => k.toLowerCase() === "cookie")) e.cookiesSent = true;
  if (r.initiator?.url) e.initiator.add(isSame(r.initiator.url) ? "same-origin script" : r.initiator.url);
  third.set(u.host, e);
}

// §10 perf / caching / protocol
const timed = reqs.filter((r) => r.finished?.durationMs !== undefined);
const slowest = [...timed].sort((a, b) => b.finished.durationMs - a.finished.durationMs).slice(0, 10);
const totalBytes = reqs.reduce((n, r) => n + (r.finished?.encodedDataLength || 0), 0);
const protoMix = new Map();
const cacheHits = { disk: 0, serviceWorker: 0 };
let compressed = 0, uncompressedText = 0, redirects = 0, e4xx = 0, e5xx = 0;
const mixedContent = [];
for (const r of reqs) {
  const h = respHeadersOf(r);
  const p = r.response?.protocol; if (p) protoMix.set(p, (protoMix.get(p) || 0) + 1);
  if (r.response?.fromDiskCache) cacheHits.disk++;
  if (r.response?.fromServiceWorker) cacheHits.serviceWorker++;
  if (r.redirect) redirects++;
  const s = statuses(r);
  if (s && s >= 400 && s < 500) e4xx++;
  if (s && s >= 500) e5xx++;
  const ce = Object.entries(h).find(([k]) => k.toLowerCase() === "content-encoding")?.[1];
  const mime = r.response?.mimeType || "";
  if (ce && !/identity/i.test(String(ce))) compressed++;
  else if (/^(text\/|application\/(json|javascript|xml))/.test(mime)) uncompressedText++;
  if (cap.target.startsWith("https:") && schemeOf(r.url) === "http:") mixedContent.push(r.url);
}

// §11 console / errors / security log
const consoleRows = cap.console || [];
const errorRows = cap.errors || [];
const secRows = cap.securityLog || [];
const secNotable = secRows.filter((e) => /content security policy|mixed content|refused|insecure|blocked/i.test(e.text || ""));

const frames = cap.frames || [];
const wsRows = cap.websockets || [];
const sseRows = cap.eventSource || [];

// ---------------------------------------------------------------- render
const dateStr = String(cap.startedAt || new Date().toISOString()).slice(0, 10);
const m = [];

m.push(`# romero browser report — ${esc(hostOf(cap.target))} ${dateStr}`);
m.push("");
m.push(`> Captured by \`capture.mjs\` from \`${esc(cap.target)}\` · ${esc(cap.startedAt)} → ${esc(cap.endedAt)}`);
m.push(`> (${esc(cap.mode)}, ${esc(cap.browser?.name || "chromium")}) — rendered by \`report.mjs\` from \`${inPath}\`.`);
m.push(`> **Observation report, not a verdict** — values are shown raw and this file never`);
m.push(`> left the machine. Production-readiness calls: \`mr-robot\`.`);
m.push("");

// §1 summary
m.push(`## 1. Summary`);
m.push("");
m.push(`- **${cap.counts?.requests ?? reqs.length} requests** · ${new Set(reqs.map((r) => hostOf(r.url))).size} host(s) · ${cap.counts?.responses ?? 0} responses · ${cap.counts?.failed ?? 0} failed · ${redirects} redirect hop(s)`);
m.push(`- **Cookies:** ${cap.cookies?.pre?.length ?? 0} before → **${jar.length} after** capture · **storage harvested on ${storage.length} origin(s)** · ${wsRows.length} WebSocket(s) / ${sseRows.length} SSE message(s)`);
m.push(`- **Bytes on the wire:** ${totalBytes.toLocaleString()} · **console:** ${consoleRows.length} message(s), ${errorRows.length} JS error(s), ${secRows.length} security-log entr(ies)`);
m.push(`- **Third parties contacted:** ${third.size ? [...third.keys()].join(", ") : "none"}`);
if (prePhase) m.push(`- \`${prePhase}\` request(s) pre-date the recorded phase (browser setup / pre-login)`);
m.push(`- Slowest call: ${slowest[0] ? `${slowest[0].finished.durationMs}ms — \`${esc(slowest[0].method)} ${esc(slowest[0].url)}\`` : "—"}`);
m.push("");

// §2 pages & frames
m.push(`## 2. Pages & frames`);
m.push("");
m.push(`| Kind | URL |`);
m.push(`|---|---|`);
for (const p of cap.pages || []) m.push(`| ${esc(p.kind)} | \`${esc(p.url)}\` |`);
m.push("");
if (cap.mainFrameNavs?.length) {
  m.push(`Main-frame navigations observed:`);
  m.push("");
  for (const n of cap.mainFrameNavs) m.push(`1. \`${esc(n.url)}\` @ ${esc(n.at)}`);
  m.push("");
}
if (frames.length > 1) {
  m.push(`Frame tree (${frames.length} frames):`);
  m.push("");
  m.push(`| Frame | Origin | URL |`);
  m.push(`|---|---|---|`);
  for (const f of frames) m.push(`| ${esc(f.frameId).slice(0, 12)} | ${esc(f.securityOrigin)} | \`${esc(short(f.url, 120))}\` |`);
  m.push("");
}
if (cap.manifest?.url) m.push(`App manifest: \`${esc(cap.manifest.url)}\` (${cap.manifest.data ? `${cap.manifest.data.length} bytes` : "no data"}, ${cap.manifest.errors?.length || 0} parse errors)`);
m.push("");

// §3 API surface
m.push(`## 3. API surface (same-origin endpoints)`);
m.push("");
if (groups.size) {
  m.push(`| Method | Path | Calls | Statuses | Kind | Query params | Notes |`);
  m.push(`|---|---|---|---|---|---|---|`);
  const sorted = [...groups.entries()].sort((a, b) => b[1].n - a[1].n);
  for (const [, g] of sorted) {
    const notes = [];
    if (g.authHdr) notes.push(`auth: ${g.authHdr}`);
    if (g.post) notes.push(`${g.post.kind} body: ${g.post.fields.slice(0, 8).join(", ")}${g.post.fields.length > 8 ? "…" : ""}`);
    if (g.post?.graphql) notes.push(`**GraphQL ${esc(g.post.graphql.operation)}**`);
    if (g.times.length) notes.push(`max ${Math.max(...g.times)}ms`);
    m.push(`| ${g.method} | \`${esc(g.tmpl)}\` | ${g.n} | ${[...g.statuses].sort().join(", ")} | ${[...g.types].join("/")} | ${esc([...g.queries].join(", ") || "—")} | ${esc(notes.join(" · ") || "—")} |`);
  }
  m.push("");
} else m.push(`_No same-origin requests recorded._`, "");

if (wsRows.length) {
  m.push(`**WebSockets:**`);
  m.push("");
  m.push(`| URL | Frames (sent/received) | Handshake | Sample first frame |`);
  m.push(`|---|---|---|---|`);
  for (const w of wsRows) {
    const sent = w.frames.filter((f) => f.dir === "sent").length, recv = w.frames.length - sent;
    const sample = w.frames[0] ? `${w.frames[0].dir}: ${short(w.frames[0].data, 90)}` : "—";
    m.push(`| \`${esc(w.url)}\` | ${sent}/${recv}${w.frameCount > w.frames.length ? ` (of ${w.frameCount} captured)` : ""} | ${w.handshake?.status ? esc(w.handshake.status) : "—"} | ${esc(sample)} |`);
  }
  m.push("");
}
if (sseRows.length) {
  m.push(`**Server-sent events:**`);
  m.push("");
  const byUrl = new Map();
  for (const e of sseRows) { const k = e.url; if (!byUrl.has(k)) byUrl.set(k, []); byUrl.get(k).push(e); }
  for (const [u, evs] of byUrl) m.push(`- \`${esc(u)}\` — ${evs.length} message(s), events: ${esc([...new Set(evs.map((e) => e.eventName || "(unnamed)"))].join(", "))}, last data: \`${esc(short(evs[evs.length - 1].data, 140))}\``);
  m.push("");
}

// §4 request headers
m.push(`## 4. Request-header inventory`);
m.push("");
const reqHdr = requestHeaderInventory(reqs);
if (reqHdr.size) {
  m.push(`| Header | Sent on | Example value |`);
  m.push(`|---|---|---|`);
  for (const [k, e] of [...reqHdr.entries()].sort((a, b) => b[1].n - a[1].n)) {
    m.push(`| \`${esc(k)}\` | ${e.n}/${reqs.length} | \`${esc(short(e.example, 120))}\`${e.extraOnly ? " _(extraInfo only)_" : ""} |`);
  }
} else m.push(`_No request headers recorded._`);
m.push("");

// §5 response headers + checklist
m.push(`## 5. Response headers & security-header checklist`);
m.push("");
const checklistRows = [];
for (const [name, re, why] of checklistDefs) {
  const hits = sameReqs.filter((r) => Object.keys(respHeadersOf(r)).some((k) => re.test(k)));
  const example = hits.length ? Object.entries(respHeadersOf(hits[0])).find(([k]) => re.test(k))?.[1] : null;
  checklistRows.push({ name, why, hits: hits.length, example });
}
const httpsTarget = cap.target.startsWith("https:");
const hsts = checklistRows.find((c) => c.name === "Strict-Transport-Security");
if (!httpsTarget && hsts) hsts.hits = -1; // N/A on http
m.push(`| Header | Same-origin responses (of ${sameReqs.length}) | Why it matters |`);
m.push(`|---|---|---|`);
for (const c of checklistRows) {
  const cell = c.hits === -1 ? `_n/a (http target)_` : c.hits ? `✅ ${c.hits} — \`${esc(short(c.example, 90))}\`` : `❌ **MISSING**`;
  m.push(`| ${c.name} | ${cell} | ${c.why} |`);
}
m.push("");
const respHdrFreq = headerInventory(sameReqs);
m.push(`All response headers seen (same-origin, ${sameReqs.length} responses):`);
m.push("");
m.push(`| Header | Present on | Example value |`);
m.push(`|---|---|---|`);
for (const [k, e] of [...respHdrFreq.entries()].sort((a, b) => b[1].n - a[1].n)) {
  m.push(`| \`${esc(k)}\` | ${e.n} | \`${esc(short(e.example, 110))}\` |`);
}
m.push("");
const acao = [...respHdrFreq.entries()].filter(([k]) => /access-control-allow/i.test(k));
if (acao.length) {
  m.push(`**CORS observed:** ${acao.map(([k, e]) => `\`${k}: ${short(e.example, 90)}\``).join(" · ")}`);
  m.push("");
}

// §6 cookies
m.push(`## 6. Cookies`);
m.push("");
if (jar.length) {
  m.push(`Jar after capture (${jar.length}):`);
  m.push("");
  m.push(`| Name | Domain | Path | Expires | Flags | Value |`);
  m.push(`|---|---|---|---|---|---|`);
  for (const c of jar) {
    const flags = [c.httpOnly && "HttpOnly", c.secure && "Secure", c.sameSite && `SameSite=${c.sameSite}`].filter(Boolean).join(", ") || "—";
    const exp = c.session ? "session" : c.expires > 0 ? new Date(c.expires * 1000).toISOString() : String(c.expires);
    m.push(`| \`${esc(c.name)}\` | ${esc(c.domain)} | ${esc(c.path)} | ${esc(exp)} | ${esc(flags)} | \`${esc(short(c.value, 80))}\` |`);
  }
  m.push("");
} else m.push(`_Cookie jar empty after capture._`, "");
if (setEvents.length) {
  m.push(`Set-Cookie events (in order):`);
  m.push("");
  m.push(`| Cookie | Set by | Attributes |`);
  m.push(`|---|---|---|`);
  for (const e of setEvents) m.push(`| \`${esc(e.name)}\` | \`${esc(short(e.url, 70))}\` | ${esc(e.flags.join(", ") || "(none)")} |`);
  m.push("");
}
for (const s of storage) {
  if (s.documentCookie) m.push(`\`document.cookie\` @ ${esc(s.origin)} (visible to JS): \`${esc(s.documentCookie)}\``);
}
if (storage.some((s) => s.documentCookie)) m.push("");

// §7 storage
m.push(`## 7. Browser storage (the Application tab)`);
m.push("");
if (!storage.length) m.push(`_No storage harvested._`, "");
for (const s of storage) {
  m.push(`### ${esc(s.origin)}${s.truncated ? " _(values truncated — full values in capture.json)_" : ""}`);
  m.push("");
  const bags = [["localStorage", s.localStorage], ["sessionStorage", s.sessionStorage]];
  for (const [label, bag] of bags) {
    const entries = Object.entries(bag || {});
    if (!entries.length) { m.push(`- **${label}:** empty`); continue; }
    m.push(`- **${label}** (${entries.length}):`);
    for (const [k, v] of entries) m.push(`  - \`${esc(k)}\` = \`${esc(short(v, 300))}\``);
  }
  if (s.documentCookie) m.push(`- **document.cookie:** \`${esc(s.documentCookie)}\``);
  if (s.indexedDB?.length) {
    m.push(`- **IndexedDB:**`);
    for (const d of s.indexedDB) {
      m.push(`  - \`${esc(d.name)}\` (v${esc(d.version ?? "?")})`);
      for (const st of d.stores || []) m.push(`    - store \`${esc(st.name)}\`: ${st.count ?? "?"} record(s), keys: ${esc((st.sampleKeys || []).map((k) => short(k, 60)).join(", ") || "—")}`);
    }
  } else m.push(`- **IndexedDB:** none`);
  if (s.cacheStorage?.length) {
    m.push(`- **Cache Storage:**`);
    for (const c of s.cacheStorage) m.push(`  - \`${esc(c.name)}\`: ${c.total} entr(ies) — ${esc((c.urls || []).slice(0, 5).map((u) => short(u, 80)).join(", "))}${c.total > 5 ? " …" : ""}`);
  } else m.push(`- **Cache Storage:** none`);
  if (s.serviceWorkers?.length) {
    m.push(`- **Service workers:**`);
    for (const w of s.serviceWorkers) m.push(`  - \`${esc(w.scope)}\` → ${esc(w.scriptURL)} (${esc(w.state)})`);
  } else m.push(`- **Service workers:** none`);
  if (s.manifest) m.push(`- **Manifest:** \`${esc(s.manifest.href)}\` — status ${s.manifest.status}, ${short(s.manifest.body, 120)}`);
  m.push("");
}
m.push(`**User agent:** ${esc(storage[0]?.userAgent || cap.browser?.userAgent || "—")}`);
m.push("");

// §8 tokens
m.push(`## 8. Tokens & credentials in traffic`);
m.push("");
if (tokens.length) {
  m.push(`| Where | Kind | Detail | Value |`);
  m.push(`|---|---|---|---|`);
  const seen = new Set();
  for (const t of tokens) {
    const key = `${t.where}|${t.kind}|${t.detail}|${t.value}`;
    if (seen.has(key)) continue; seen.add(key);
    m.push(`| \`${esc(short(t.where, 70))}\` | ${esc(t.kind)} | ${esc(short(t.detail, 140))} | \`${esc(short(t.value, 240))}\` |`);
  }
  m.push("");
  if (jwts.size) {
    m.push(`**JWT payloads decoded locally:**`);
    m.push("");
    for (const [tok, where] of jwts) {
      const claims = decodeJwt(tok);
      m.push(`- \`${esc(short(tok, 70))}…\` seen at ${esc(short([...new Set(where)].join(" · "), 200))}`);
      if (claims) for (const [k, v] of Object.entries(claims)) m.push(`  - \`${k}\` = \`${esc(short(JSON.stringify(v), 160))}\``);
    }
    m.push("");
  }
} else m.push(`_No tokens, credentials, or secret-shaped strings found in headers, URLs, bodies, cookies, or storage._`, "");

// §9 third parties
m.push(`## 9. Third-party contacts & data flows`);
m.push("");
if (third.size) {
  m.push(`| Host | Requests | Types | Schemes | Cookies sent? | Query params sent | Body fields sent | Pulled by |`);
  m.push(`|---|---|---|---|---|---|---|---|`);
  for (const e of [...third.values()].sort((a, b) => b.n - a.n)) {
    m.push(`| \`${esc(e.host)}\` | ${e.n} | ${esc([...e.types].join("/"))} | ${esc([...e.schemes].join(","))} | ${e.cookiesSent ? "**yes** ⚠️" : "no"} | ${esc([...e.params].join(", ") || "—")} | ${esc([...e.post].join(", ") || "—")} | ${esc([...e.initiator].join(", ") || "—")} |`);
  }
  m.push("");
  m.push(`_Every row above ran inside the user's browser as part of loading the page — that is exactly the third-party exposure a visitor inherits._`);
} else m.push(`_No third-party hosts contacted — everything was same-origin._`);
m.push("");

// §10 performance
m.push(`## 10. Performance, caching & protocol`);
m.push("");
m.push(`- **Protocol mix:** ${[...protoMix.entries()].map(([p, n]) => `${p} ×${n}`).join(" · ") || "—"}`);
m.push(`- **Compression:** ${compressed} response(s) with Content-Encoding · ${uncompressedText} uncompressed text/JSON response(s)`);
m.push(`- **Cache:** ${cacheHits.disk} from disk cache · ${cacheHits.serviceWorker} from service worker`);
m.push(`- **Outcomes:** ${redirects} redirect hop(s) · ${e4xx} 4xx · ${e5xx} 5xx · ${totalBytes.toLocaleString()} bytes total`);
if (mixedContent.length) {
  m.push(`- ⚠️ **Mixed content** — insecure \`http:\` resources on an \`https:\` page:`);
  for (const u of [...new Set(mixedContent)].slice(0, 20)) m.push(`  - \`${esc(u)}\``);
}
m.push("");
if (slowest.length) {
  m.push(`Slowest calls:`);
  m.push("");
  m.push(`| ms | Status | Bytes | Call |`);
  m.push(`|---|---|---|---|`);
  for (const r of slowest) m.push(`| ${r.finished.durationMs} | ${statuses(r) ?? "—"} | ${r.finished.encodedDataLength ?? 0} | \`${esc(r.method)} ${esc(short(r.url, 90))}\` |`);
  m.push("");
}

// §11 console / errors / security log
m.push(`## 11. Console, JS errors & security log`);
m.push("");
const typeCount = new Map();
for (const c of consoleRows) typeCount.set(c.type, (typeCount.get(c.type) || 0) + 1);
m.push(`Console: ${[...typeCount.entries()].map(([t, n]) => `${t} ×${n}`).join(" · ") || "empty"}`);
if (consoleRows.length) {
  m.push("");
  for (const c of consoleRows.slice(0, 30)) m.push(`- \`${esc(c.type)}\` ${esc(short(c.text, 220))}`);
  if (consoleRows.length > 30) m.push(`- _…${consoleRows.length - 30} more in capture.json_`);
}
m.push("");
if (errorRows.length) {
  m.push(`JS errors (${errorRows.length}):`);
  m.push("");
  for (const e of errorRows.slice(0, 20)) m.push(`- ${esc(short(e.text, 260))}${e.url ? ` @ \`${esc(short(e.url, 100))}\`` : ""}`);
  m.push("");
}
if (secRows.length) {
  m.push(`Security-relevant log entries: ${secNotable.length ? `**${secNotable.length} notable** of ${secRows.length}` : `${secRows.length} (none flagged as CSP/mixed-content/refusal)`}`);
  m.push("");
  for (const e of (secNotable.length ? secNotable : secRows).slice(0, 20)) m.push(`- \`${esc(e.source)}/${esc(e.level)}\` ${esc(short(e.text, 240))}${e.url ? ` @ \`${esc(short(e.url, 90))}\`` : ""}`);
  m.push("");
}

// §12 observations & coverage
m.push(`## 12. Observations & coverage`);
m.push("");
const obs = [];
const missing = checklistRows.filter((c) => c.hits === 0 && c.name !== "Strict-Transport-Security").map((c) => c.name);
if (missing.length) obs.push(`Security headers missing on every same-origin response: ${missing.join(", ")} (§5).`);
if (httpsTarget && hsts && hsts.hits === 0) obs.push(`No \`Strict-Transport-Security\` on an HTTPS target (§5).`);
for (const c of jar) {
  if (c.secure && !c.httpOnly) obs.push(`Cookie \`${c.name}\` is Secure but NOT HttpOnly — readable by JS (§6).`);
  if (!c.secure && httpsTarget) obs.push(`Cookie \`${c.name}\` lacks \`Secure\` on an HTTPS site (§6).`);
  if (c.sameSite === "None" && !c.secure) obs.push(`Cookie \`${c.name}\` is SameSite=None without Secure (§6).`);
}
for (const s of storage) for (const [k, v] of Object.entries({ ...s.localStorage, ...s.sessionStorage })) {
  if (/eyJ[\w-]+\./.test(String(v))) obs.push(`JWT stored in browser storage (\`${k}\` @ ${s.origin}) — any XSS can read it (§7).`);
  else if (/token|secret|key|cred|pass/i.test(k)) obs.push(`Sensitive-looking storage key \`${k}\` @ ${s.origin} (§7).`);
}
const urlSecrets = tokens.filter((t) => t.where === "URL query");
if (urlSecrets.length) obs.push(`${urlSecrets.length} credential-shaped value(s) in URL query strings — they leak via history, Referer and logs (§8).`);
if (mixedContent.length) obs.push(`${mixedContent.length} insecure http:// resource(s) on an https page (§10).`);
const wildcardCors = [...respHdrFreq.entries()].filter(([k, e]) => /access-control-allow-origin/i.test(k) && /\*/.test(String(e.example)));
if (wildcardCors.length) obs.push(`\`Access-Control-Allow-Origin: *\` observed — verify no credentialed cross-origin reads (§5).`);
if (third.size) {
  const cookieLeak = [...third.values()].filter((e) => e.cookiesSent);
  if (cookieLeak.length) obs.push(`Third-party host(s) receiving cookies: ${cookieLeak.map((e) => e.host).join(", ")} (§9).`);
}
const serverHdr = [...respHdrFreq.entries()].filter(([k]) => /^(server|x-powered-by|x-aspnet-version|x-runtime)$/i.test(k));
if (serverHdr.length) obs.push(`Version disclosure: ${serverHdr.map(([k, e]) => `${k}=${short(e.example, 40)}`).join(", ")} (§5).`);
if (errorRows.length) obs.push(`${errorRows.length} uncaught JS error(s) during capture (§11).`);
if (cap.loadTimedOutPages?.length) obs.push(`${cap.loadTimedOutPages.length} page(s) never went fully idle — long-poll/SSE or slow assets (see coverage below).`);

if (obs.length) { for (const o of obs) m.push(`- ${o}`); } else m.push(`- No heuristic observations fired.`);
m.push("");
m.push(`**Coverage (honest scope):**`);
m.push("");
m.push(`- Captured: \`${esc(cap.target)}\`${(cap.pages || []).length > 1 ? ` + ${cap.pages.length - 1} route(s)` : ""} — ${reqs.length} requests recorded${cap.budget?.exceeded ? ` (**budget ${cap.budget.max} EXCEEDED** — ${cap.budget.observed} observed; scope was cut)` : ` (budget ${cap.budget?.max ?? "—"}, ${cap.budget?.observed ?? reqs.length} observed)`}.`);
m.push(`- Storage harvested on ${storage.length} origin(s): ${esc(storage.map((s) => s.origin).join(", ") || "none")} — state written *after* the final harvest (or on origins never navigated to live) is not visible to a passive capture.`);
m.push(`- Response bodies captured for XHR/fetch/Document only, mime-filtered, ${cap.counts?.bodyBytes ?? 0} bytes total — stylesheet/script/image bodies are excluded by design.`);
m.push(`- WS frames capped per socket; IndexedDB values recorded as counts + sample keys (full values live only where the app keeps them).`);
m.push(`- **No clicks, no form submissions, no crawling** — only page loads (plus whatever the app itself requested${prePhase ? " and your manual login during the pause" : ""}). Interactive flows (checkout, uploads) are NOT exercised; run those yourself in --headed mode if they matter.`);
if (cap.loadTimedOutPages?.length) for (const p of cap.loadTimedOutPages) m.push(`- ⏱ \`${esc(p.url)}\`: ${esc(p.reason)}`);
m.push(`- Values are raw (no redaction) because capture + report both stay on this machine.`);
m.push("");
m.push(`---`);
m.push(`_Structure: SKILL.md Phase 2 · capture: capture.mjs (schema mr-romero-capture-v1) · verdicts: mr-robot (this report issues none)._`);
m.push("");

const md = m.join("\n");
if (outPath) {
  writeFileSync(outPath, md);
  const sections = (md.match(/^## \d+\./gm) || []).length;
  process.stderr.write(`[romero] wrote ${outPath} — ${sections} sections, ${tokens.length} token row(s), ${obs.length} observation(s)\n`);
} else {
  process.stdout.write(md);
}
process.exit(0);
