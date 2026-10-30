#!/usr/bin/env node
// mr-robot — bounded mutation fuzzer + binary hardening check (references/09-fuzz-binary.md).
//
//   Usage:
//     fuzz-lane.mjs --checksec <binary> [--out <file.json>]
//     fuzz-lane.mjs [--budget S] [--seed N] [--corpus <dir>] [--timeout MS]
//                   [--max <n>] [--out <file.json>] -- <cmd> [args...]
//
// Fuzz mode runs YOUR local build against seeded, deterministically mutated
// inputs: '@@' in args is replaced by the input file path, otherwise input goes
// to stdin. Classification: exit >=128 / killed signal = crash; sanitizer or
// panic keywords in output (AddressSanitizer, stack smashing, panicked at,
// SIGSEGV/ABRT, fatal runtime) = crash; per-run timeout = hang (recorded, not
// verdict-changing). The first crash stops the run — reproduce, don't exploit:
// no payload is ever developed from a crashing input.
//
// --checksec reads the binary's own headers (readelf on Linux, otool/nm on
// macOS) and reports PIE / NX / RELRO / stack-canary with the evidence line —
// 'unknown' is reported rather than guessed.
//
// Bounds (Phase 0, non-negotiable): local builds only — cmd[0] must not be a
// URL/remote transport (refused); budget ≤600s (default 60), per-run timeout
// ≤10s (default 2000ms), iterations ≤5000 (default 1000); inputs ≤64 KiB;
// seeded PRNG (--seed) makes every run — including a crash — exactly
// repeatable. Crash inputs are saved beside --out (or embedded ≤256B base64
// in the report when no --out is given).
//
// Exit codes:
// 0 no crash within budget · 1 crash found (candidate — reproduce with the
//   same --seed, triage per 09) · 2 usage · 3 target/tool unavailable
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const log = (m) => process.stdout.write(`[fuzz] ${m}\n`);
function die(msg, code) {
  process.stderr.write(`REFUSED: ${msg}\nusage: fuzz-lane.mjs --checksec <binary> | fuzz-lane.mjs [flags] -- <cmd> [args...]\n`);
  process.exit(code);
}

// ------------------------------------------------------------------ CLI
const argv = process.argv.slice(2);
if (argv.includes("-h") || argv.includes("--help")) {
  const src = readFileSync(new URL(import.meta.url), "utf8").split("\n");
  const end = src.findIndex((l) => l.includes("Exit codes:"));
  process.stdout.write(src.slice(1, end + 2).map((l) => l.replace(/^\/\/ ?/, "")).join("\n") + "\n");
  process.exit(0);
}
let budget = 60, seed = 1337, corpusDir = null, timeoutMs = 2000, maxIter = 1000, outPath = null;
let checksecBin = null;
const sep = argv.indexOf("--");
const flags = sep === -1 ? argv : argv.slice(0, sep);
const cmd = sep === -1 ? [] : argv.slice(sep + 1);
const num = (v, name) => {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) die(`${name} needs a positive number`, 2);
  return Math.floor(n);
};
for (let i = 0; i < flags.length; i++) {
  const a = flags[i];
  if (a === "--checksec") { checksecBin = flags[++i]; if (!checksecBin) die("--checksec needs a binary path", 2); }
  else if (a === "--budget") budget = num(flags[++i], "--budget");
  else if (a === "--seed") seed = num(flags[++i], "--seed");
  else if (a === "--corpus") { corpusDir = flags[++i]; if (!corpusDir) die("--corpus needs a directory", 2); }
  else if (a === "--timeout") timeoutMs = num(flags[++i], "--timeout");
  else if (a === "--max") maxIter = num(flags[++i], "--max");
  else if (a === "--out") { outPath = flags[++i]; if (!outPath) die("--out needs a file", 2); }
  else die(`unknown flag ${a}`, 2);
}
budget = Math.min(budget, 600);
timeoutMs = Math.min(timeoutMs, 10_000);
maxIter = Math.min(maxIter, 5000);
if (!checksecBin && cmd.length === 0) die("nothing to run — pass -- <cmd> or --checksec <binary>", 2);
if (checksecBin && cmd.length) die("--checksec and fuzz mode are exclusive", 2);

// ------------------------------------------------------------- checksec
const CAP = { pie: null, nx: null, relro: null, canary: null };
function out(doc) {
  if (outPath) { mkdirSync(dirname(resolve(outPath)), { recursive: true }); writeFileSync(outPath, JSON.stringify(doc, null, 1)); }
}
function checksec() {
  const bin = resolve(checksecBin);
  if (!existsSync(bin) || !statSync(bin).isFile()) die(`not a file: ${checksecBin}`, 3);
  const r = (c, a) => spawnSync(c, a, { encoding: "utf8", timeout: 10_000 });
  const basis = {};
  let tool = null;
  if (r("readelf", ["--version"]).status === 0) {
    tool = "readelf";
    const h = r("readelf", ["-h", bin]).stdout || "";
    basis.pie = /Type:\s+DYN/.test(h) ? "ELF Type: DYN (PIE)" : /Type:\s+EXEC/.test(h) ? "ELF Type: EXEC (not PIE)" : "unreadable ELF header";
    CAP.pie = /Type:\s+DYN/.test(h);
    const l = r("readelf", ["-lW", bin]).stdout || "";
    const stackLine = l.split("\n").find((line) => /GNU_STACK/.test(line)) || "";
    const flagsM = stackLine.match(/0x[0-9a-f]+\s+([RWE ]+)\s/);
    // NX is ON when the E (executable) flag is absent from GNU_STACK's flags
    const nx = flagsM ? !flagsM[1].includes("E") : null;
    CAP.nx = nx;
    basis.nx = stackLine
      ? (nx === null ? "GNU_STACK flags unreadable" : nx ? "GNU_STACK flags without E (NX on)" : "GNU_STACK marked executable")
      : "no GNU_STACK note";
    const relroSeg = /GNU_RELRO/.test(l);
    const d = r("readelf", ["-d", bin]).stdout || "";
    const bindNow = /BIND_NOW/.test(d) || /FLAGS[^)]*\bDF_BIND_NOW\b/.test(d);
    CAP.relro = relroSeg ? (bindNow ? "full" : "partial") : "none";
    basis.relro = relroSeg ? (bindNow ? "GNU_RELRO + BIND_NOW (full)" : "GNU_RELRO only (partial)") : "no GNU_RELRO segment";
    const s = r("readelf", ["-sW", bin]).stdout || "";
    CAP.canary = /__stack_chk_fail/.test(s);
    basis.canary = CAP.canary ? "__stack_chk_fail present" : "no __stack_chk_fail symbol";
  } else if (r("otool", ["-hv", bin]).status === 0) {
    tool = "otool+nm";
    const hv = r("otool", ["-hv", bin]).stdout || "";
    CAP.pie = /\bPIE\b/.test(hv);
    basis.pie = CAP.pie ? "PIE in Mach-O header flags" : "no PIE flag in Mach-O header flags";
    CAP.nx = null;
    basis.nx = "unknown — macOS enforces NX by platform policy (no per-binary flag to read)";
    CAP.relro = null;
    basis.relro = "unknown — check on macOS via dyld chained-fixups/bind-now tooling";
    const nm = r("nm", [bin]).stdout || "";   // NOT -gU: stack_chk is an *undefined* (imported) symbol
    CAP.canary = /stack_chk/.test(nm);
    basis.canary = CAP.canary ? "___stack_chk_fail/guard imported" : "no stack_chk symbol (imported or local)";
  } else {
    die("neither readelf nor otool available for --checksec", 3);
  }
  const row = (k, label) => {
    const v = CAP[k] === null ? "unknown" : String(CAP[k]);
    log(`  ${label.padEnd(6)} ${v.padEnd(8)} (${basis[k]})`);
  };
  log(`checksec: ${checksecBin}  [${tool}]`);
  row("pie", "PIE"); row("nx", "NX"); row("relro", "RELRO"); row("canary", "canary");
  const doc = { schema: "mr-robot-fuzz-v1", mode: "checksec", binary: checksecBin, tool, properties: CAP, basis,
                generated_at: new Date().toISOString() };
  out(doc);
  if (outPath) log(`  ${outPath}`);
  process.exit(0);
}
if (checksecBin) checksec();

// ------------------------------------------------------------ fuzz mode
// local builds only: refuse a URL executable AND any non-loopback http(s)/ftp
// URL argument (a fixed remote URL + mutated stdin = unbounded remote traffic)
const REMOTE = /^(https?|ftp|ssh|scp|sftp):/i;
const LOOPBACK = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])([:/]|$)/i;
if (REMOTE.test(cmd[0])) die(`remote target '${cmd[0]}' — this lane runs local builds only`, 3);
for (const a of cmd.slice(1)) {
  const m = a.match(REMOTE);
  if (m && !LOOPBACK.test(a)) die(`non-loopback URL in arguments (${a.slice(0, 60)}) — local targets only`, 3);
}

// seeded PRNG — mulberry32; identical --seed ⇒ identical run, including a crash
function rng(s) {
  let a = s >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = rng(seed);
const ri = (n) => Math.floor(rand() * n);
const pick = (arr) => arr[ri(arr.length)];
const MAX_INPUT = 65_536;

const BUILTIN_SEEDS = [
  Buffer.alloc(64, 0x41),
  Buffer.from('{"id":1,"name":"mr-robot","items":[1,2,3]}'),
  Buffer.from("<root><item key='v'>x</item></root>"),
  Buffer.from("%PDF-1.4\n1 0 obj\n<<>>\nendobj\n"),
  Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0x7f, 0x80, 0x0a, 0x0d, 0x00]),
  Buffer.from("A".repeat(4096)),
];
const pool = [];
if (corpusDir) {
  if (!existsSync(corpusDir) || !statSync(corpusDir).isDirectory()) die(`not a directory: ${corpusDir}`, 3);
  for (const f of readdirSync(corpusDir)) {
    const p = join(corpusDir, f);
    if (statSync(p).isFile() && pool.length < 64) pool.push(readFileSync(p).subarray(0, MAX_INPUT));
  }
  if (!pool.length) die(`no readable seed files in ${corpusDir}`, 3);
} else pool.push(...BUILTIN_SEEDS);

// Buffer is a Uint8Array — no splice method; build one on concat (returns new)
const spliceB = (buf, start, del, ...items) =>
  Buffer.concat([buf.subarray(0, start), Buffer.from(items), buf.subarray(start + del)]);
const OPS = ["bitflip", "byteflip", "interesting", "insert", "delete", "dup", "truncate", "lenprefix"];
function mutate(buf) {
  let b = Buffer.from(buf);
  const apply = () => {
    switch (pick(OPS)) {
      case "bitflip": { if (!b.length) break; const i = ri(b.length); b = spliceB(b, i, 1, b[i] ^ (1 << ri(8))); break; }
      case "byteflip": { if (!b.length) break; const i = ri(b.length); b = spliceB(b, i, 1, pick([0x00, 0xff, 0x7f, 0x80, 0x0a, 0x0d, 0x41])); break; }
      case "interesting": { const i = ri(b.length + 1); b = spliceB(b, i, 0, 0x00, 0x00, 0x00, 0x00); break; }
      case "insert": { const i = ri(b.length + 1); const junk = Buffer.alloc(1 + ri(32), pick([0x41, 0x00, 0xff])); b = spliceB(b, i, 0, ...junk); break; }
      case "delete": { if (b.length > 4) { const i = ri(b.length - 3); b = spliceB(b, i, 1 + ri(Math.min(16, b.length - i))); } break; }
      case "dup": { if (b.length > 4 && b.length < MAX_INPUT / 2) { const i = ri(b.length - 3); const n = Math.min(64, b.length - i); b = spliceB(b, i, 0, ...b.subarray(i, i + n)); } break; }
      case "truncate": { if (b.length > 8) b = b.subarray(0, 1 + ri(b.length - 1)); break; }
      case "lenprefix": { const head = Buffer.alloc(4); head.writeUInt32LE(b.length + 1024); b = Buffer.concat([head, b]); break; }
    }
  };
  apply(); apply();   // two ops per input — small corpus, fast signal
  const r = b.subarray(0, MAX_INPUT);
  return r.length ? r : Buffer.from("A");
}

const CRASH_KEYS = /AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|LeakSanitizer|stack smashing detected|panicked at|SIGSEGV|SIGABRT|fatal runtime error|Aborted|heap-use-after-free|heap-buffer-overflow|stack-overflow/;
const hasFileArg = cmd.some((a) => a.includes("@@"));
const tmp = hasFileArg ? join(process.env.TMPDIR || "/tmp", `mr-robot-fuzz-${process.pid}`) : null;
if (tmp) mkdirSync(tmp, { recursive: true });
const inputPath = tmp ? join(tmp, "input") : null;

function runOnce(buf) {
  if (inputPath) writeFileSync(inputPath, buf);
  const args = cmd.slice(1).map((a) => a.split("@@").join(inputPath ?? "@@"));
  const t0 = Date.now();
  const r = spawnSync(cmd[0], args, {
    input: inputPath ? undefined : buf,
    timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"],
  });
  const elapsed = Date.now() - t0;
  if (r.error && r.error.code === "ENOENT") die(`target not runnable: ${cmd[0]}`, 3);
  if (r.error && r.error.code === "EACCES") die(`not executable: ${cmd[0]}`, 3);
  const outTxt = `${r.stderr?.toString("latin1") || ""}\n${r.stdout?.toString("latin1") || ""}`;
  const timedOut = r.error?.code === "ETIMEDOUT" || (r.signal && elapsed >= timeoutMs - 50);
  if (timedOut) return { kind: "hang", status: r.status, signal: r.signal, out: outTxt.slice(0, 600) };
  if (r.signal) return { kind: "crash", how: `killed by ${r.signal}`, status: r.status, signal: r.signal, out: outTxt.slice(0, 2000) };
  if (typeof r.status === "number" && r.status >= 128) return { kind: "crash", how: `exit ${r.status} (128+signal)`, status: r.status, signal: null, out: outTxt.slice(0, 2000) };
  if (CRASH_KEYS.test(outTxt)) {
    const m = outTxt.match(CRASH_KEYS);
    return { kind: "crash", how: `sanitizer/panic keyword: ${m[0]}`, status: r.status, signal: null, out: outTxt.slice(0, 2000) };
  }
  return { kind: "ok", status: r.status, out: "" };
}

log(`target: ${cmd.join(" ")}  · mode: ${inputPath ? "file @@" : "stdin"}  · seed ${seed}  · budget ${budget}s  · timeout ${timeoutMs}ms`);
const runStart = Date.now();
const deadline = runStart + budget * 1000;
const crashes = [];
const hangs = [];
let iter = 0;
let phase = 0;   // 0: raw seeds (deterministic first look), 1: mutations
outer:
while (iter < maxIter && Date.now() < deadline) {
  let input;
  if (phase < pool.length) { input = pool[phase++]; }
  else input = mutate(pick(pool));
  iter++;
  const res = runOnce(input);
  if (res.kind === "crash") {
    crashes.push({ iteration: iter, how: res.how, status: res.status, signal: res.signal,
                   input_b64: input.subarray(0, 256).toString("base64"), input_bytes: input.length,
                   output_excerpt: res.out.slice(0, 600) });
    if (outPath) {
      const dir = `${resolve(outPath)}.crashes`;
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, `crash-${iter}.bin`), input);
      writeFileSync(join(dir, `crash-${iter}.log`), res.out);
      crashes[crashes.length - 1].artifact = join(dir, `crash-${iter}.bin`);
    }
    break outer;   // bounded proof: first crash is the finding — reproduce, don't spray
  }
  if (res.kind === "hang" && hangs.length < 10) hangs.push({ iteration: iter, timeout_ms: timeoutMs });
}

const doc = {
  schema: "mr-robot-fuzz-v1", mode: "fuzz", generated_at: new Date().toISOString(),
  cmd, seed, budget_s: budget, timeout_ms: timeoutMs, iterations: iter, max_iterations: maxIter,
  corpus: corpusDir || "builtin", delivery: inputPath ? "@@file" : "stdin",
  crashes, hangs, verdict: crashes.length ? "crash" : "no-crash",
};
out(doc);

for (const c of crashes) {
  log(`CRASH at iteration ${c.iteration}: ${c.how}${c.artifact ? ` — input saved ${c.artifact}` : ` — input(b64, first 256B): ${c.input_b64}`}`);
  log(`  output: ${c.output_excerpt.split("\n").filter(Boolean).slice(0, 3).join(" | ").slice(0, 300)}`);
}
if (hangs.length) log(`${hangs.length} hang(s) recorded (timeout ${timeoutMs}ms) — triage as potential DoS per 09, not verdict-changing here`);
log(`${iter} iteration(s) in ${Math.round((Date.now() - runStart) / 1000)}s — ${crashes.length ? "CRASH FOUND (candidate: reproduce with the same --seed, then triage)" : "no crash within budget"}`);
if (outPath) log(`  ${outPath}`);
process.exit(crashes.length ? 1 : 0);
