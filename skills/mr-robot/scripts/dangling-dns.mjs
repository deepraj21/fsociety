#!/usr/bin/env node
// mr-robot — dangling-DNS / subdomain-takeover screen (references/01-recon.md §7).
//
//   Usage:
//     dangling-dns.mjs <target-dir> [--out <file.json>]
//     dangling-dns.mjs <target-dir> --resolve [--limit <n>]
//
// SOURCE MODE (default — zero network): scans config/source files for first-party
// hostnames and for references to known takeovers-prone providers (herokuapp,
// github.io, s3, azurewebsites, cloudfront, netlify, vercel, shopify, zendesk …).
// Every hostname found is a *candidate* to hand to an operator for the claim
// check — the script makes no DNS query and never claims anything itself.
//
// --resolve (opt-in, bounded ≤50): for each candidate it resolves the CNAME
// chain; when the CNAME target matches a known provider suffix AND the provider
// hostname itself no longer resolves (NXDOMAIN / ENOTFOUND), the record is
// DANGLING — someone forgot the resource while the DNS still points at it.
// Resolution only; it never registers, claims, or touches the provider.
//
// Output: {"schema":"mr-robot-dangling-dns-v1", mode, scanned, candidates:
// [{host, provider?, via, file}], resolved?: [{host, cname, provider, state}],
// dangling?: [...]}. scan-all.sh merges findings into findings.json.
//
// Bounds: source walk ≤3000 files, ≤4096 B per file; resolve ≤50 CNAME lookups
// (+≤50 target existence checks), 3s per lookup. Exit codes:
// 0 source-mode complete, or resolve-mode with no dangling · 1 dangling found ·
// 2 usage · 3 unusable (not a directory / unreadable).

import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, extname } from "node:path";
import { promises as dns } from "node:dns";

function die(msg, code) {
  process.stderr.write(`REFUSED: ${msg}\nusage: dangling-dns.mjs <target-dir> [--out <file.json>] [--resolve] [--limit <n>]\n`);
  process.exit(code);
}

// Known takeovers-prone providers: a first-party name CNAMEing here is only as
// safe as the provider resource still existing (CWE-350).
const PROVIDERS = [
  ["herokuapp.com", "Heroku"], ["herokudns.com", "Heroku"],
  ["github.io", "GitHub Pages"], ["githubusercontent.com", "GitHub"],
  ["s3.amazonaws.com", "AWS S3"], ["s3-website", "AWS S3 website"],
  ["cloudfront.net", "AWS CloudFront"], ["awsapprunner.com", "AWS App Runner"],
  ["azurewebsites.net", "Azure App Service"], ["cloudapp.azure.com", "Azure"],
  ["azureedge.net", "Azure CDN"], ["trafficmanager.net", "Azure Traffic Manager"],
  ["cloudapp.net", "Azure Cloud Service"],
  ["netlify.app", "Netlify"], ["netlify.com", "Netlify"],
  ["vercel.app", "Vercel"], ["now.sh", "Vercel"],
  ["shopify.com", "Shopify"], ["myshopify.com", "Shopify"],
  ["fastly.net", "Fastly"], ["fastlylb.net", "Fastly"],
  ["zendesk.com", "Zendesk"], ["zendesk-iad", "Zendesk"],
  ["ghost.io", "Ghost"], ["pantheon.io", "Pantheon"], ["wpengine.com", "WP Engine"],
  ["wordpress.com", "WordPress.com"], ["tumblr.com", "Tumblr"],
  ["webflow.io", "Webflow"], ["unbounce.com", "Unbounce"],
  ["bitbucket.io", "Bitbucket Pages"], ["readthedocs.io", "Read the Docs"],
  ["statuspage.io", "Statuspage"], ["cargo.site", "Cargo"], ["surge.sh", "Surge"],
  ["fly.dev", "Fly.io"], ["onrender.com", "Render"], ["railway.app", "Railway"],
  ["replit.dev", "Replit"], ["firebaseapp.com", "Firebase"], ["web.app", "Firebase"],
];

const SKIP_DIRS = new Set([".git", "node_modules", "vendor", "dist", "build",
  ".next", "target", "__pycache__", ".venv", "venv"]);
const SKIP_EXT = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
  ".zip", ".gz", ".tar", ".woff", ".woff2", ".ttf", ".mp4", ".mov", ".so", ".dylib",
  ".exe", ".bin", ".class", ".jar", ".wasm", ".db", ".sqlite", ".lock"]);
const MAX_FILES = 3000, MAX_BYTES = 4096, DEFAULT_LIMIT = 50;
// hostname-ish token with at least one dot, TLD 2+ letters
const HOST_RE = /\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24})\b/gi;

function providerOf(host) {
  const h = host.toLowerCase();
  for (const [suffix, name] of PROVIDERS) if (h.endsWith("." + suffix) || h === suffix) return name;
  return null;
}

function* walk(dir, budget) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (budget.n <= 0) return;
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) yield* walk(join(dir, e.name), budget); }
    else if (e.isFile()) { budget.n--; yield join(dir, e.name); }
  }
}

async function withTimeout(promise, ms) {
  let t;
  const timeout = new Promise((_, rej) => { t = setTimeout(() => rej(new Error("timeout")), ms); });
  try { return await Promise.race([promise, timeout]); } finally { clearTimeout(t); }
}

// ------------------------------------------------------------------ CLI
const args = process.argv.slice(2);
let target = null, outPath = null, resolveMode = false, limit = DEFAULT_LIMIT;
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "-h" || a === "--help") {
    const src = readFileSync(new URL(import.meta.url), "utf8").split("\n");
    const end = src.findIndex((l) => l.includes("Exit codes:"));
    process.stdout.write(src.slice(1, end + 3).map((l) => l.replace(/^\/\/ ?/, "")).join("\n") + "\n");
    process.exit(0);
  } else if (a === "--out") { outPath = args[++i]; if (!outPath) die("--out needs a file", 2); }
  else if (a === "--resolve") resolveMode = true;
  else if (a === "--limit") { limit = parseInt(args[++i], 10); if (!Number.isFinite(limit) || limit < 1) die("--limit needs a positive integer", 2); }
  else if (a.startsWith("-")) die(`unknown flag ${a}`, 2);
  else if (target) die("exactly one <target-dir> expected", 2);
  else target = a;
}
target = target || ".";
if (!existsSync(target) || !statSync(target).isDirectory()) die(`not a directory: ${target}`, 3);

// ------------------------------------------------------------------ source scan
const candidates = new Map(); // host -> {host, provider?, via, file}
const budget = { n: MAX_FILES };
for (const file of walk(target, budget)) {
  if (SKIP_EXT.has(extname(file).toLowerCase())) continue;
  let text;
  try {
    if (statSync(file).size > MAX_BYTES) continue;
    text = readFileSync(file, "utf8");
  } catch { continue; }
  if (text.includes("\u0000")) continue; // binary
  for (const m of text.matchAll(HOST_RE)) {
    const host = m[1].toLowerCase();
    const provider = providerOf(host);
    // source mode: record provider references (the takeover surface) and
    // plausible first-party hosts sitting next to them in the same file
    if (provider && !candidates.has(host)) {
      candidates.set(host, { host, provider, via: "provider-reference", file });
    }
  }
}

const result = {
  schema: "mr-robot-dangling-dns-v1",
  mode: resolveMode ? "resolve" : "source",
  scanned: candidates.size,
  candidates: [...candidates.values()].map(({ host, provider, via, file }) => ({ host, provider, via, file })),
};

// ------------------------------------------------------------------ resolve (opt-in)
if (resolveMode) {
  result.resolved = [];
  result.dangling = [];
  const work = result.candidates.slice(0, limit);
  for (const c of work) {
    let cname = null, state = "no-cname";
    try {
      const chain = await withTimeout(dns.resolveCname(c.host), 3000);
      cname = chain[0]?.name || null;
    } catch (e) {
      state = ["ENOTFOUND", "ENODATA"].includes(e.code) ? "no-cname" : `error:${e.code || e.message}`;
    }
    if (cname) {
      const provider = providerOf(cname);
      if (provider) {
        state = "cname-active";
        try { await withTimeout(dns.lookup(cname), 3000); }
        catch (e) {
          if (e.code === "ENOTFOUND" || e.message === "timeout") {
            state = e.message === "timeout" ? "target-timeout" : "dangling";
            if (state === "dangling") result.dangling.push({ host: c.host, cname, provider, state });
          }
        }
      } else state = "cname-unlisted-provider";
    }
    result.resolved.push({ host: c.host, cname, provider: providerOf(cname || "") || undefined, state });
  }
  result.resolvedN = result.resolved.length;
}

if (outPath) { try { writeFileSync(outPath, JSON.stringify(result, null, 2) + "\n"); } catch (e) { die(`cannot write ${outPath}: ${e.message}`, 3); } }
else process.stdout.write(JSON.stringify(result, null, 2) + "\n");

if (resolveMode && result.dangling.length > 0) {
  process.stderr.write(`NOTE: ${result.dangling.length} dangling record(s) — verify ownership before any claim (01-recon §7)\n`);
  process.exit(1);
}
process.exit(0);
