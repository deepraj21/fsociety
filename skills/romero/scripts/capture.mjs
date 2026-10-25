#!/usr/bin/env node
// romero — capture EVERYTHING a browser sees at a live product URL.
//
//   node capture.mjs <url> [options]
//
//   --out <dir>        output directory (default ./romero-capture-<timestamp>)
//   --headed           visible window; pauses after first load so the USER can
//                       log in manually (press Enter) — credentials never touch
//                       this script. Headless by default.
//   --route <path>     extra same-origin route to load after the entry URL
//                       (repeatable; absolute http(s) URLs also accepted)
//   --budget <n>       request cap (default 500, hard max 2000). On exceed:
//                       no further routes, no more response bodies; flagged.
//   --timeout <sec>    hard deadline for the whole capture (default 120)
//   --browser <path>   browser binary (default: CHROME_PATH env, Chrome, Brave…)
//   --no-login         with --headed: skip the login pause
//
// Zero npm dependencies: Node's built-in WebSocket + fetch speak the Chrome
// DevTools Protocol directly against a system browser (Chrome/Brave/Edge) that
// is launched in an ISOLATED temp profile — never the user's own profile.
//
// What is recorded: every request/response with full headers both ways (and
// bodies for XHR/fetch/Document, capped), redirect hops, timing, HTTP version,
// cache/service-worker provenance, WebSocket frames, SSE events, the cookie
// jar before/after, per-origin browser storage (localStorage, sessionStorage,
// IndexedDB, Cache Storage, service workers, document.cookie), app manifest,
// frame tree, console output, JS errors and the security log.
//
// Outputs:  <out>/capture.json  (schema mr-romero-capture-v1, values RAW —
//            the report is for the operator's machine, no redaction)
//           <out>/capture.har   (HAR 1.2 — opens in any DevTools/HAR viewer)
//
// Scope discipline (this is an OBSERVER, not an attacker): only http/https
// targets, ordinary page loads only — no fuzzing, no mutation, no exploits.
// Exit: 0 capture complete · 1 runtime failure · 2 usage/environment refusal.

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { setTimeout as sleep } from "node:timers/promises";

const CAP_SCHEMA = "mr-romero-capture-v1";
const BODY_PER_CAP = 512 * 1024;      // per response body
const BODY_TOTAL_CAP = 20 * 1024 * 1024; // across the capture
const POSTDATA_CAP = 64 * 1024;
const STORAGE_VALUE_CAP = 64 * 1024;
const STORAGE_TOTAL_CAP = 4 * 1024 * 1024;
const WS_FRAME_CAP = 4096;
const WS_FRAME_COUNT_CAP = 400;
const BODY_MIME_OK = /^(text\/|application\/(json|javascript|xml|x-www-form-urlencoded|.*\+json|.*\+xml))/i;

function die(msg, code = 2) {
  process.stderr.write(`REFUSED: ${msg}\nusage: capture.mjs <url> [--out <dir>] [--headed] [--route <path>]... [--budget <n>] [--timeout <sec>] [--browser <path>] [--no-login]\n`);
  process.exit(code);
}
function log(msg) { process.stdout.write(`[romero] ${msg}\n`); }

// ------------------------------------------------------------------ CLI
const args = process.argv.slice(2);
let entryUrl = null, outDir = null, browserOverride = null, headed = false, loginPause = true;
let budget = 500, hardDeadlineMs = 120_000;
const routes = [];
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--out") { outDir = args[++i]; if (!outDir) die("--out needs a directory"); }
  else if (a === "--headed") headed = true;
  else if (a === "--no-login") loginPause = false;
  else if (a === "--route") { const r = args[++i]; if (!r) die("--route needs a path"); routes.push(r); }
  else if (a === "--budget") { budget = Number(args[++i]); if (!Number.isFinite(budget) || budget < 1) die("--budget must be a positive number"); budget = Math.min(Math.floor(budget), 2000); }
  else if (a === "--timeout") { const s = Number(args[++i]); if (!Number.isFinite(s) || s < 10) die("--timeout must be >= 10 seconds"); hardDeadlineMs = s * 1000; }
  else if (a === "--browser") { browserOverride = args[++i]; if (!browserOverride) die("--browser needs a path"); }
  else if (a.startsWith("-")) die(`unknown flag ${a}`);
  else if (entryUrl) die("exactly one <url> expected");
  else entryUrl = a;
}
if (!entryUrl) die("missing <url>");
let entry;
try { entry = new URL(entryUrl); } catch { die(`not a URL: ${entryUrl}`); }
if (entry.protocol !== "http:" && entry.protocol !== "https:") die(`only http/https targets — got ${entry.protocol}`);
if (!outDir) outDir = `romero-capture-${new Date().toISOString().replace(/[-:]/g, "").slice(0, 15).replace("T", "-")}`;
mkdirSync(outDir, { recursive: true });

// ----------------------------------------------------------- browser pick
if (browserOverride && !existsSync(browserOverride)) die(`browser not found: ${browserOverride}`);
if (process.env.CHROME_PATH && !existsSync(process.env.CHROME_PATH)) die(`CHROME_PATH not found: ${process.env.CHROME_PATH}`);
function findBrowser() {
  const cands = [
    browserOverride, process.env.CHROME_PATH,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome-stable", "/usr/bin/google-chrome", "/usr/bin/chromium",
    "/usr/bin/chromium-browser", "/snap/bin/chromium", "/microsoft-edge",
  ].filter(Boolean);
  for (const c of cands) if (existsSync(c)) return c;
  return null;
}
const browserBin = findBrowser();
if (!browserBin) die("no Chrome/Brave/Edge found — install one or pass --browser <path> / set CHROME_PATH");

// ----------------------------------------------------------- capture state
const startedWall = Date.now();
const cap = {
  schema: CAP_SCHEMA,
  target: entry.href,
  startedAt: new Date(startedWall).toISOString(),
  endedAt: null,
  phaseStart: null,
  mode: headed ? "headed" : "headless",
  browser: null,
  pages: [],          // user intents (entry + routes)
  mainFrameNavs: [],  // observed main-frame navigations (incl. redirects)
  requests: [],
  websockets: [],
  eventSource: [],
  console: [],
  errors: [],
  securityLog: [],    // Log.entryAdded (mixed content, CSP-ish warnings)
  cookies: { pre: [], post: [] },
  storage: [],
  frames: null,
  manifest: null,
  loadTimedOutPages: [],
  budget: { max: budget, exceeded: false, observed: 0 },
  coverage: { routesPlanned: routes.length, routesCompleted: 0, truncatedRequests: 0 },
};
cap.pages.push({ url: entry.href, kind: "entry" });
for (const r of routes) cap.pages.push({ url: r, kind: "route" });

const reqById = new Map();     // requestId → current hop record
const wsById = new Map();
const bodyJobs = [];
let bodyBytesTotal = 0;
let lastNewReqMono = Date.now();
let loadFiredAt = 0;
let seq = 0;
let reqSeq = 0;
let hardDeadlineAt = startedWall + hardDeadlineMs;

// cookie jar: Network.getAllCookies was removed from the browser target in
// modern Chrome — try the session-level call first, then Storage.getCookies.
async function getJar(session) {
  for (const [m, p, s] of [["Network.getAllCookies", {}, session],
                           ["Storage.getCookies", {}, session],
                           ["Storage.getCookies", {}, undefined]]) {
    try {
      const r = await send(m, p, s);
      if (Array.isArray(r.cookies)) return r.cookies;
    } catch { /* next strategy */ }
  }
  return [];
}

// ------------------------------------------------------------- CDP client
let ws, chrome, profileDir, chromeStderr = "";
const pending = new Map();
const eventHandlers = new Map();

function on(method, fn) {
  if (!eventHandlers.has(method)) eventHandlers.set(method, []);
  eventHandlers.get(method).push(fn);
}
function send(method, params = {}, sessionId) {
  return new Promise((res, rej) => {
    const id = ++seq;
    const to = setTimeout(() => { pending.delete(id); rej(new Error(`CDP timeout: ${method}`)); }, 30_000);
    pending.set(id, {
      res: (v) => { clearTimeout(to); res(v); },
      rej: (e) => { clearTimeout(to); rej(e); },
    });
    ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
}
async function connect(wsUrl) {
  ws = new WebSocket(wsUrl);
  await new Promise((res, rej) => {
    const to = setTimeout(() => rej(new Error("WebSocket connect timeout")), 15_000);
    ws.onopen = () => { clearTimeout(to); res(); };
    ws.onerror = () => { clearTimeout(to); rej(new Error("DevTools WebSocket error")); };
  });
  ws.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.id !== undefined && pending.has(m.id)) {
      const p = pending.get(m.id); pending.delete(m.id);
      m.error ? p.rej(new Error(`${m.error.message} (${m.error.code ?? ""})`)) : p.res(m.result ?? {});
    } else if (m.method) {
      for (const fn of eventHandlers.get(m.method) || []) {
        try { fn(m.params ?? {}, m.sessionId); } catch { /* recording must never crash */ }
      }
    }
  };
}

// --------------------------------------------------------------- helpers
const iso = (mono, wall) =>
  wall ? new Date(wall * 1000).toISOString()
       : new Date(startedWall - (firstMono - mono) * 1000).toISOString();
let firstMono = null;
function trunc(s, n) {
  if (typeof s !== "string") return s;
  return s.length > n ? s.slice(0, n) + `…[truncated ${s.length - n} chars]` : s;
}
function initiatorOf(init) {
  if (!init) return null;
  const f = init.stack?.callFrames?.[0];
  return { type: init.type ?? null, url: init.url ?? (f ? f.url : null),
           stackTop: f ? `${f.url}:${f.lineNumber + 1}` : null };
}
function headersToArr(h) { return Object.entries(h || {}).map(([name, value]) => ({ name, value: String(value) })); }

// ------------------------------------------------------------ main flow
let sessionId = null;

async function navAndWait(url, label, pageTimeoutMs = 20_000) {
  lastNewReqMono = Date.now(); loadFiredAt = 0;
  const t0 = Date.now();
  let timedOut = false;
  try { await send("Page.navigate", { url }, sessionId); }
  catch (e) { log(`navigation failed (${label}): ${e.message}`); cap.loadTimedOutPages.push({ url, reason: e.message }); return; }
  for (;;) {
    if (Date.now() >= hardDeadlineAt) { timedOut = true; break; }
    if (loadFiredAt && Date.now() - lastNewReqMono > 900) break;
    if (Date.now() - t0 > pageTimeoutMs) { timedOut = true; break; }
    await sleep(200);
  }
  if (timedOut) cap.loadTimedOutPages.push({ url, reason: Date.now() >= hardDeadlineAt ? "hard-deadline" : "network never went idle (long-poll/SSE or slow assets)" });
  await sleep(300); // let stragglers record
}

async function harvestStorage() {
  const r = await send("Runtime.evaluate", { expression: HARVEST_SRC, awaitPromise: true, returnByValue: true }, sessionId);
  const val = r.result?.value;
  if (!val) return;
  try {
    const parsed = JSON.parse(val);
    // value caps
    let total = 0, truncAny = false;
    for (const bag of [parsed.localStorage, parsed.sessionStorage]) {
      for (const [k, v] of Object.entries(bag)) {
        total += String(v).length;
        if (String(v).length > STORAGE_VALUE_CAP) { bag[k] = trunc(v, STORAGE_VALUE_CAP); truncAny = true; }
        if (total > STORAGE_TOTAL_CAP) { bag[k] = "[storage total cap reached]"; truncAny = true; break; }
      }
    }
    parsed.truncated = truncAny;
    parsed.harvestedAt = new Date().toISOString();
    // last harvest for an origin wins
    const existing = cap.storage.findIndex((s) => s.origin === parsed.origin);
    if (existing >= 0) cap.storage[existing] = parsed; else cap.storage.push(parsed);
  } catch { /* JSON parse failure — ignore */ }
}

// in-page harvest (kept as source so no shell quoting ever touches it)
const HARVEST_SRC = `
(async () => {
  const out = { origin: location.origin, localStorage: {}, sessionStorage: {},
    indexedDB: [], cacheStorage: [], serviceWorkers: [], documentCookie: "",
    manifest: null, userAgent: navigator.userAgent };
  const sync = (fn, dflt) => { try { return fn(); } catch (e) { return dflt; } };
  const asafe = async (fn, dflt) => { try { return await fn(); } catch (e) { return dflt; } };
  sync(() => { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); out.localStorage[k] = localStorage.getItem(k); } });
  sync(() => { for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i); out.sessionStorage[k] = sessionStorage.getItem(k); } });
  out.documentCookie = sync(() => document.cookie, "");
  await asafe(async () => {
    const dbs = await indexedDB.databases();
    for (const d of dbs) {
      if (!d.name) continue;
      const rec = { name: d.name, version: d.version || null, stores: [] };
      await new Promise((done) => {
        let req; try { req = indexedDB.open(d.name); } catch (e) { done(); return; }
        const guard = setTimeout(done, 2500);
        req.onerror = () => { clearTimeout(guard); done(); };
        req.onsuccess = () => {
          const db = req.result;
          try {
            const names = Array.from(db.objectStoreNames || []);
            if (!names.length) { clearTimeout(guard); try { db.close(); } catch (e) {} done(); return; }
            const tx = db.transaction(names, "readonly");
            for (const n of names) {
              const st = tx.objectStore(n);
              const entry = { name: n, count: null, sampleKeys: [] };
              rec.stores.push(entry);
              const c = sync(() => st.count(), null);
              if (c) { c.onsuccess = () => { entry.count = c.result; }; }
              const cur = sync(() => st.openCursor(), null);
              if (cur) cur.onsuccess = () => {
                const cr = cur.result;
                if (cr && entry.sampleKeys.length < 20) { entry.sampleKeys.push(String(cr.key).slice(0, 200)); cr.continue(); }
              };
            }
            tx.oncomplete = () => { clearTimeout(guard); try { db.close(); } catch (e) {} done(); };
            tx.onerror = () => { clearTimeout(guard); try { db.close(); } catch (e) {} done(); };
          } catch (e) { clearTimeout(guard); try { db.close(); } catch (e2) {} done(); }
        };
      });
      out.indexedDB.push(rec);
    }
  }, null);
  await asafe(async () => {
    const keys = await caches.keys();
    for (const k of keys) {
      const c = await caches.open(k);
      const rs = await c.keys();
      out.cacheStorage.push({ name: k, total: rs.length, urls: rs.slice(0, 100).map((r) => r.url) });
    }
  }, null);
  await asafe(async () => {
    const regs = await navigator.serviceWorker.getRegistrations();
    for (const r of regs) {
      const sw = r.active || r.waiting || r.installing;
      out.serviceWorkers.push({ scope: r.scope, scriptURL: sw ? sw.scriptURL : null, state: sw ? sw.state : null });
    }
  }, null);
  await asafe(async () => {
    const link = document.querySelector('link[rel="manifest"]');
    if (link && link.href) {
      const resp = await fetch(link.href, { credentials: "same-origin" });
      out.manifest = { href: link.href, status: resp.status, body: trunc(await resp.text(), 16384) };
    }
  }, null);
  function trunc(s, n) { return s.length > n ? s.slice(0, n) + "…[truncated]" : s; }
  return JSON.stringify(out);
})()
`;

// ---------------------------------------------------------- CDP recording
function wireRecording(session) {
  on("Network.requestWillBeSent", (p, sid) => {
    if (sid !== session) return;
    lastNewReqMono = Date.now();
    cap.budget.observed++;
    if (cap.budget.observed > 2000) { cap.coverage.truncatedRequests++; return; }
    if (p.redirectResponse) {
      const prev = reqById.get(p.requestId);
      if (prev) prev.redirect = {
        status: p.redirectResponse.status, statusText: p.redirectResponse.statusText || "",
        headers: p.redirectResponse.headers || {}, protocol: p.redirectResponse.protocol || null,
        mimeType: p.redirectResponse.mimeType || null,
        location: p.redirectResponse.headers?.Location ?? p.redirectResponse.headers?.location ?? null,
      };
    }
    if (p.wallTime && firstMono === null) firstMono = p.timestamp;
    const rec = {
      id: p.requestId,
      sequence: ++reqSeq,
      url: p.request.url,
      method: p.request.method,
      type: p.type || "Other",
      documentURL: p.documentURL || null,
      initiator: initiatorOf(p.initiator),
      ts: p.timestamp,
      wallTime: p.wallTime || null,
      startedAt: iso(p.timestamp, p.wallTime),
      headers: p.request.headers || {},
      postData: p.request.postData ? trunc(p.request.postData, POSTDATA_CAP) : null,
      response: null, extraHeaders: null, reqExtraHeaders: null, finished: null, failed: null, body: null, redirect: null,
    };
    cap.requests.push(rec);
    reqById.set(p.requestId, rec);
  });

  on("Network.responseReceived", (p, sid) => {
    if (sid !== session) return;
    const rec = reqById.get(p.requestId); if (!rec) return;
    const r = p.response || {};
    rec.type = p.type || rec.type;
    rec.response = {
      status: r.status, statusText: r.statusText || "", mimeType: r.mimeType || "",
      protocol: r.protocol || null, remoteIPAddress: r.remoteIPAddress || null,
      fromDiskCache: !!r.fromDiskCache, fromServiceWorker: !!r.fromServiceWorker,
      timing: r.timing || null, headers: r.headers || {},
      securityDetails: r.securityDetails ? {
        protocol: r.securityDetails.protocol, issuer: r.securityDetails.issuer,
        subjectName: r.securityDetails.subjectName,
        validFrom: r.securityDetails.validFrom, validTo: r.securityDetails.validTo,
      } : null,
    };
  });

  on("Network.responseReceivedExtraInfo", (p, sid) => {
    if (sid !== session) return;
    const rec = reqById.get(p.requestId); if (!rec) return;
    rec.extraHeaders = p.headers || null;
    if (Array.isArray(p.rawHeaders) && p.rawHeaders.length) rec.rawHeaderPairs = p.rawHeaders;
  });

  on("Network.requestWillBeSentExtraInfo", (p, sid) => {
    if (sid !== session) return;
    const rec = reqById.get(p.requestId); if (!rec) return;
    rec.reqExtraHeaders = p.headers || null;
    // Chrome sometimes withholds the Cookie header from requestWillBeSent —
    // the raw copy arrives here (keys may differ in case: match case-insensitively)
    const haveCookie = Object.keys(rec.headers).some((k) => k.toLowerCase() === "cookie");
    const ck = Object.entries(p.headers || {}).find(([k]) => k.toLowerCase() === "cookie");
    if (!haveCookie && ck) rec.headers = { ...rec.headers, [ck[0]]: ck[1] };
  });

  on("Network.loadingFinished", (p, sid) => {
    if (sid !== session) return;
    const rec = reqById.get(p.requestId); if (!rec) return;
    // real end time: request-start wall clock + monotonic delta (wallTime is
    // the START — deriving endedAt from it directly would zero every duration)
    const startWallMs = rec.wallTime ? rec.wallTime * 1000 : startedWall;
    rec.finished = {
      encodedDataLength: p.encodedDataLength || 0,
      endedAt: new Date(startWallMs + (p.timestamp - rec.ts) * 1000).toISOString(),
      durationMs: Math.max(0, Math.round((p.timestamp - rec.ts) * 1000)),
    };
    const mime = rec.response?.mimeType || "";
    const okType = /^(XHR|Fetch|Document)$/.test(rec.type);
    if (okType && BODY_MIME_OK.test(mime) && !cap.budget.exceeded &&
        bodyBytesTotal < BODY_TOTAL_CAP && rec.response?.status !== 204 &&
        !rec.response?.fromDiskCache) {
      bodyJobs.push((async () => {
        try {
          const b = await send("Network.getResponseBody", { requestId: p.requestId }, sessionId);
          const text = b.base64Encoded ? b.body : trunc(b.body, BODY_PER_CAP);
          const size = b.body.length;
          if (bodyBytesTotal + size <= BODY_TOTAL_CAP) {
            bodyBytesTotal += size;
            rec.body = { text, encoding: b.base64Encoded ? "base64" : "text", truncated: b.base64Encoded ? false : text !== b.body };
          }
        } catch { /* body gone (redirect/cache) — fine */ }
      })());
    }
  });

  on("Network.loadingFailed", (p, sid) => {
    if (sid !== session) return;
    const rec = reqById.get(p.requestId); if (!rec) return;
    rec.failed = { errorText: p.errorText || "", canceled: !!p.canceled, blockedReason: p.blockedReason || null, type: p.type || null };
  });

  on("Network.webSocketCreated", (p, sid) => {
    if (sid !== session) return;
    const e = { id: p.requestId, url: p.url, initiator: p.initiator || null, openedAt: new Date().toISOString(), closedAt: null, frames: [], handshake: null, frameCount: 0 };
    wsById.set(p.requestId, e); cap.websockets.push(e);
  });
  on("Network.webSocketWillSendHandshakeRequest", (p, sid) => {
    if (sid !== session) return;
    const e = wsById.get(p.requestId); if (e) e.handshake = { requestHeaders: p.request?.headers || {}, at: new Date().toISOString() };
  });
  on("Network.webSocketHandshakeResponse", (p, sid) => {
    if (sid !== session) return;
    const e = wsById.get(p.requestId); if (!e) return;
    e.handshake = { ...(e.handshake || {}), status: p.status, responseHeaders: p.headers || {}, at: new Date().toISOString() };
  });
  const frame = (dir) => (p, sid) => {
    if (sid !== session) return;
    const e = wsById.get(p.requestId); if (!e) return;
    e.frameCount++;
    if (e.frames.length >= WS_FRAME_COUNT_CAP) return;
    e.frames.push({ dir, opcode: p.response?.opcode, data: trunc(p.response?.data ?? "", WS_FRAME_CAP), at: new Date().toISOString() });
  };
  on("Network.webSocketFrameSent", frame("sent"));
  on("Network.webSocketFrameReceived", frame("received"));
  on("Network.webSocketFrameError", (p, sid) => {
    if (sid !== session) return;
    const e = wsById.get(p.requestId); if (e) e.frameError = p.errorMessage;
  });
  on("Network.webSocketClosed", (p, sid) => {
    if (sid !== session) return;
    const e = wsById.get(p.requestId); if (e) e.closedAt = new Date().toISOString();
  });

  on("Network.eventSourceMessageReceived", (p, sid) => {
    if (sid !== session) return;
    cap.eventSource.push({ url: p.url, eventName: p.eventName || null, id: p.id ?? null, data: trunc(p.data ?? "", WS_FRAME_CAP), at: new Date().toISOString() });
  });

  on("Page.frameNavigated", (p, sid) => {
    if (sid !== session) return;
    if (!p.frame.parentId) cap.mainFrameNavs.push({ url: p.frame.url, frameId: p.frame.id, at: new Date().toISOString() });
  });
  on("Page.loadEventFired", (_p, sid) => { if (sid === session) loadFiredAt = Date.now(); });
  on("Page.lifecycleEvent", (p, sid) => {
    if (sid !== session) return;
    if (p.name === "networkIdle") lastNewReqMono = 0; // definitive idle signal
    if (p.name === "load") loadFiredAt = Date.now();
  });

  on("Runtime.consoleAPICalled", (p, sid) => {
    if (sid !== session) return;
    const text = (p.args || []).map((a) => a.value !== undefined ? String(a.value) : (a.description || a.type || "")).join(" ");
    cap.console.push({ type: p.type, text: trunc(text, 4096), at: new Date(p.timestamp || Date.now()).toISOString() });
    if (cap.console.length > 500) cap.console.shift();
  });
  on("Runtime.exceptionThrown", (p, sid) => {
    if (sid !== session) return;
    const d = p.exceptionDetails || {};
    cap.errors.push({ text: trunc(`${d.text || ""} ${d.exception?.description || ""}`.trim(), 4096), url: d.url || null, line: d.lineNumber ?? null, at: new Date().toISOString() });
    if (cap.errors.length > 200) cap.errors.shift();
  });
  on("Log.entryAdded", (p, sid) => {
    if (sid !== session) return;
    const e = p.entry || {};
    cap.securityLog.push({ source: e.source, level: e.level, text: trunc(e.text || "", 4096), url: e.url || null, line: e.lineNumber ?? null });
    if (cap.securityLog.length > 300) cap.securityLog.shift();
  });
}

function promptPause(msg) {
  return new Promise((res) => {
    if (!process.stdin.isTTY) { log("stdin not a TTY — skipping login pause"); res(); return; }
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.question(msg, () => { rl.close(); res(); });
  });
}

// ---------------------------------------------------------------- cleanup
function cleanup() {
  try { ws?.close(); } catch { /* */ }
  if (chrome && chrome.exitCode === null) { try { chrome.kill("SIGTERM"); } catch { /* */ } }
  if (profileDir) { try { rmSync(profileDir, { recursive: true, force: true, maxRetries: 3 }); } catch { /* */ } }
}
process.on("SIGINT", () => { cleanup(); process.exit(130); });

// ------------------------------------------------------------------ main
async function main() {
  log(`launching ${browserBin} (${headed ? "headed — login pause enabled" : "headless"}, isolated profile)`);
  profileDir = mkdtempSync(join(tmpdir(), "romero-profile-"));
  chrome = spawn(browserBin, [
    ...(headed ? [] : ["--headless"]),
    "--remote-debugging-port=0", `--user-data-dir=${profileDir}`,
    "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
    "--disable-component-update", "--disable-sync", "--disable-extensions",
    "--disable-translate", "--mute-audio", "--hide-scrollbars", "--disable-gpu",
    "--disable-dev-shm-usage", "--window-size=1440,900", "about:blank",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  chrome.stderr.on("data", (d) => { chromeStderr += d.toString(); if (chromeStderr.length > 64_000) chromeStderr = chromeStderr.slice(-32_000); });
  let chromeGone = null;
  chrome.on("exit", (code) => { chromeGone = code; });

  // discover devtools endpoint (port file, stderr fallback)
  const portFile = join(profileDir, "DevToolsActivePort");
  let wsUrl = null;
  for (let i = 0; i < 150 && !wsUrl; i++) {
    if (chromeGone !== null) die(`browser exited early (code ${chromeGone}): ${chromeStderr.slice(-600)}`, 1);
    if (existsSync(portFile)) {
      try {
        const [port] = readFileSync(portFile, "utf8").split("\n");
        if (port) {
          const r = await fetch(`http://127.0.0.1:${port}/json/version`);
          const j = await r.json();
          if (j.webSocketDebuggerUrl) wsUrl = j.webSocketDebuggerUrl;
          cap.browser = { name: j.Browser || browserBin, protocol: j["Protocol-Version"] || null, userAgent: j["User-Agent"] || null };
        }
      } catch { /* not ready */ }
    }
    if (!wsUrl) {
      const m = chromeStderr.match(/DevTools listening on (ws:\/\/\S+)/);
      if (m) wsUrl = m[1];
    }
    if (!wsUrl) await sleep(100);
  }
  if (!wsUrl) die("could not reach the browser DevTools endpoint", 1);

  await connect(wsUrl);
  const { targetId } = await send("Target.createTarget", { url: "about:blank" });
  ({ sessionId } = await send("Target.attachToTarget", { targetId, flatten: true }));
  await send("Page.enable", {}, sessionId);
  await send("Network.enable", { maxPostDataSize: POSTDATA_CAP }, sessionId);
  await send("Runtime.enable", {}, sessionId);
  await send("Log.enable", {}, sessionId);
  await send("Page.setLifecycleEventsEnabled", { enabled: true }, sessionId);
  wireRecording(sessionId);

  // cookie jar before anything (pre-login baseline) and after capture
  cap.cookies.pre = await getJar(sessionId);

  log(`loading ${entry.href}`);
  await navAndWait(entry.href, "entry");

  if (headed && loginPause) {
    await promptPause("[romero] window is yours — log in to your app, then come back and press ENTER to start the recorded phase… ");
    cap.phaseStart = new Date().toISOString();
    await sleep(1200); // settle post-login traffic
  }
  // headless / --no-login: no phase boundary — phaseStart stays null so the
  // report doesn't mislabel normal startup requests as "pre-login"
  await harvestStorage();

  // extra routes (same origin unless absolute)
  for (const r of routes) {
    if (Date.now() >= hardDeadlineAt) { log("hard deadline reached — skipping remaining routes"); break; }
    if (cap.budget.observed >= budget) { cap.budget.exceeded = true; log(`request budget ${budget} reached — skipping remaining routes`); break; }
    const abs = r.startsWith("http") ? r : new URL(r, entry.href).href;
    // mark the planned entry executed (no duplicate row in the report)
    const planned = cap.pages.find((p) => p.kind === "route" && (p.url === r || p.url === abs));
    if (planned) { planned.url = abs; planned.kind = "route executed"; }
    else cap.pages.push({ url: abs, kind: "route executed" });
    log(`loading route ${abs}`);
    await navAndWait(abs, "route");
    await harvestStorage();
    cap.coverage.routesCompleted++;
  }
  if (cap.budget.observed > budget) cap.budget.exceeded = true;

  // final state
  await Promise.allSettled(bodyJobs);
  cap.cookies.post = await getJar(sessionId);
  try {
    const ft = await send("Page.getFrameTree", {}, sessionId);
    const flat = [];
    (function walk(n) { flat.push({ frameId: n.frame.id, url: n.frame.url, securityOrigin: n.frame.securityOrigin, name: n.frame.name || null }); (n.childFrames || []).forEach(walk); })(ft.frameTree);
    cap.frames = flat;
  } catch { /* */ }
  try {
    const m = await send("Page.getAppManifest", {}, sessionId);
    if (m && m.url) cap.manifest = { url: m.url, errors: m.errors || [], data: m.data || null };
  } catch { /* no manifest — fine */ }
}

async function finalize() {
  cap.endedAt = new Date().toISOString();
  cap.counts = {
    requests: cap.requests.length,
    requestHopsObserved: cap.budget.observed,
    responses: cap.requests.filter((r) => r.response || r.redirect).length,
    failed: cap.requests.filter((r) => r.failed).length,
    websockets: cap.websockets.length,
    wsFrames: cap.websockets.reduce((n, w) => n + w.frameCount, 0),
    sseMessages: cap.eventSource.length,
    cookiesPre: cap.cookies.pre.length,
    cookiesPost: cap.cookies.post.length,
    storageOrigins: cap.storage.length,
    console: cap.console.length,
    errors: cap.errors.length,
    securityLog: cap.securityLog.length,
    bodyBytes: bodyBytesTotal,
    durationMs: Date.parse(cap.endedAt) - Date.parse(cap.startedAt),
  };
  const jsonPath = join(outDir, "capture.json");
  writeFileSync(jsonPath, JSON.stringify(cap, null, 1));
  const har = buildHar(cap);
  const harPath = join(outDir, "capture.har");
  writeFileSync(harPath, JSON.stringify(har, null, 1));
  const uniqHosts = new Set(cap.requests.map((r) => { try { return new URL(r.url).host; } catch { return null; } }).filter(Boolean));
  log(`capture complete — ${cap.counts.requests} requests, ${uniqHosts.size} hosts, ${cap.counts.wsFrames} WS frames, ${cap.counts.sseMessages} SSE messages`);
  log(`  ${jsonPath}`);
  log(`  ${harPath}`);
  log("next: node skills/romero/scripts/report.mjs " + jsonPath + " -o " + join(outDir, "REPORT.md"));
}

function buildHar(c) {
  const entries = [];
  for (const r of c.requests) {
    let url; try { url = new URL(r.url); } catch { continue; }
    const resp = r.response || (r.redirect ? { status: r.redirect.status, statusText: r.redirect.statusText, headers: r.redirect.headers, protocol: r.redirect.protocol, mimeType: r.redirect.mimeType } : null);
    // responseReceived.headers has Set-Cookie STRIPPED by Chrome — the raw
    // copy only exists in responseReceivedExtraInfo; merge so cookies survive
    const respHeaders = { ...(resp?.headers || {}), ...(r.extraHeaders || {}) };
    const headers = r.headers || {};
    const cookieHeader = Object.entries(headers).find(([k]) => k.toLowerCase() === "cookie")?.[1] || "";
    const timing = resp?.timing;
    const t = {};
    if (timing) for (const k of ["blocked", "dns", "connect", "send", "wait", "receive", "ssl"]) if (typeof timing[k] === "number" && timing[k] >= 0) t[k] = timing[k];
    const wallMs = r.wallTime ? r.wallTime * 1000 : startedWall;
    let durationMs = 0;
    if (r.finished) {
      durationMs = typeof r.finished.durationMs === "number"
        ? r.finished.durationMs
        : Math.max(0, Date.parse(r.finished.endedAt) - wallMs);
    }
    entries.push({
      startedDateTime: new Date(wallMs).toISOString(),
      time: durationMs,
      request: {
        method: r.method, url: r.url, httpVersion: resp?.protocol || "HTTP/1.1",
        headers: headersToArr(headers),
        queryString: [...url.searchParams].map(([name, value]) => ({ name, value })),
        cookies: cookieHeader ? String(cookieHeader).split(";").map((s) => { const [n, ...v] = s.trim().split("="); return { name: n, value: v.join("=") }; }) : [],
        headersSize: -1, bodySize: r.postData ? Buffer.byteLength(r.postData) : 0,
        ...(r.postData ? { postData: { mimeType: Object.entries(headers).find(([k]) => k.toLowerCase() === "content-type")?.[1] || "", text: r.postData } } : {}),
      },
      response: {
        status: resp?.status ?? 0, statusText: resp?.statusText ?? "",
        httpVersion: resp?.protocol || "HTTP/1.1",
        headers: headersToArr(respHeaders),
        cookies: (Object.entries(respHeaders).filter(([k]) => k.toLowerCase() === "set-cookie")).flatMap(([, v]) =>
          String(v).split("\n").map((line) => {
            const first = line.split(";")[0]; const [n, ...val] = first.split("=");
            return { name: n.trim(), value: val.join("=").trim() };
          })),
        content: {
          size: r.body ? Buffer.byteLength(r.body.text, r.body.encoding === "base64" ? "base64" : "utf8") : 0,
          mimeType: resp?.mimeType || "",
          ...(r.body ? { text: r.body.text, ...(r.body.encoding === "base64" ? { encoding: "base64" } : {}) } : {}),
        },
        redirectURL: Object.entries(resp?.headers || {}).find(([k]) => k.toLowerCase() === "location")?.[1] || "",
        headersSize: -1, bodySize: r.finished?.encodedDataLength ?? 0,
        _transferSize: r.finished?.encodedDataLength ?? 0,
      },
      cache: {},
      timings: { blocked: t.blocked ?? -1, dns: t.dns ?? -1, connect: t.connect ?? -1, send: t.send ?? 0, wait: t.wait ?? 0, receive: t.receive ?? 0, ssl: t.ssl ?? -1 },
      serverIPAddress: resp?.remoteIPAddress || undefined,
      ...(r.failed ? { _failed: r.failed.errorText } : {}),
    });
  }
  return { log: { version: "1.2", creator: { name: "romero", version: "1.0" }, browser: { name: cap.browser?.name || "chrome", version: cap.browser?.protocol || "" }, pages: [], entries } };
}

try {
  await main();
  await finalize();
  cleanup();
  process.exit(0);
} catch (e) {
  process.stderr.write(`[romero] FAILED: ${e.message}\n`);
  cleanup();
  process.exit(1);
}
