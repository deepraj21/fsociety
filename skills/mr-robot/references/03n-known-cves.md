# 03n — Known-CVE verification: from "flagged version" to proven exploit path (OWASP A06:2025 · CWE-1395)

Trivy and osv-scanner answer *"is this version inside a CVE range?"* — that is a
**candidate**, not a finding: ranges lie (backported patches, distro rebuilds,
unpinned manifests), and a CVE in a lockfile says nothing about what the *deployed*
instance actually runs. This lane is the missing middle layer for the CVE class that
gets mass-exploited in the wild — framework/runtime components where a version match
against a vendor advisory **is** the exploit path:

- **JS/npm apps** — `next`, `react-server-dom-*` (React2Shell, CVSS 10.0),
  the middleware auth-bypass that rides along with old Next.js;
- **PHP apps** — the PHP core RCE fleet (PHP2Shell), `symfony/security-http`,
  `laravel/passport`, `twig/twig`.

```bash
# source-only fingerprint + version match (always safe, zero network)
node skills/mr-robot/scripts/cve-audit.mjs <target-dir> --out audit.json

# + corroborate the stack over HTTP and run the harmless header-diff probe
# (localhost ONLY — scan-all enforces loopback on --live)
node skills/mr-robot/scripts/cve-audit.mjs <target-dir> --live http://127.0.0.1:3000 \
  --path /admin --path /dashboard --out audit.json
```

`scan-all.sh` runs it as a background lane and merges `findings` into
`findings.json` (`engine: known-cve`, `aliases: [CVE-…]`); titles carry the CVE id
so the KEV enrichment pass at merge time annotates them from the local CISA cache.
Exit: `0` audit complete (match or not) · `2` usage · `3` refused (non-loopback `--live`).

## What the tool fingerprints (Detect)

| Source | Extracts |
|---|---|
| `package.json` / `package-lock.json` (v1–v3) / `yarn.lock` / `pnpm-lock.yaml` | `next`, `react-server-dom-{webpack,parcel,turbopack}` — exact version from lockfile preferred over manifest range |
| `composer.json` / `composer.lock` | `symfony/security-http`, `laravel/passport`, `twig/twig`, platform PHP |
| `Dockerfile` `FROM php:x.y.z`, `.php-version`, `.tool-versions` | PHP runtime pin |
| `--live` entry page | `X-Powered-By` PHP version (deployment truth overrides manifest) |

Bounds: source walk depth ≤6, ≤3000 files, ≤40 collected manifests — a monorepo
scan stays seconds. Unpinned manifest ranges (`^15.1.0`) are **never** matched as
vulnerable (npm resolves them to the newest patch); two-part pins (`php:8.3`) match
but are severity-downgraded with an explicit `UNPINNED` note in the evidence.

## Curated table (what the tool knows — every row cites its advisory)

| CVE | Component | Impact | Fixed in | Severity |
|---|---|---|---|---|
| CVE-2025-55182 / CVE-2025-66478 | `next` 15.x–16.0.6 (14.3.0-canary.77+) | React2Shell: pre-auth RCE via RSC Flight deserialization, single request, ~100% on default config | 15.0.5 / 15.1.9 / 15.2.6 / 15.3.6 / 15.4.8 / 15.5.7 / 16.0.7 | **critical 10.0** |
| CVE-2025-55182 | `react-server-dom-{webpack,parcel,turbopack}` 19.0.0 / 19.1.0 / 19.1.1 / 19.2.0 | same Flight deserializer flaw in the standalone packages | 19.0.1 / 19.1.2 / 19.2.1 (≥19.2.3 rec.) | **critical 10.0** |
| CVE-2025-29927 | `next` < 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3 | middleware auth bypass — one spoofed `x-middleware-subrequest` header walks past ALL middleware (EPSS 92.6) | per-branch floors above | **high 9.1** |
| CVE-2026-109618 / CVE-2026-109619 | PHP core ≤ 8.5.11 (EOL ≤8.1 unfixed) | PHP2Shell: memory corruption → unauthenticated RCE; CISA alert 2026-10-21 | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | **high 9.2** |
| CVE-2026-48489 | `symfony/security-http` < 5.4.53 / 6.4.41 / 7.4.13 | firewall bypass via failing-forward subrequest → unauthenticated access to protected routes | 5.4.53 / 6.4.41 / 7.4.13 / 8.0 | high |
| CVE-2026-39976 | `laravel/passport` 13.x < 13.7.1 | `client_credentials` machine token resolving to a real user identity | 13.7.1 | high |
| CVE-2026-24425 | `twig/twig` 2.16.* / 3.9.0–3.25.x | sandbox bypass when using a source policy → escape for apps rendering untrusted templates | 3.26.0 | medium |

Not in the table on purpose (see **Watchlist** below): the tool only carries rows
whose vulnerable/fixed ranges we sourced from vendor advisories.

## Verify → Prove → Impact (per CVE)

### CVE-2025-55182 — React2Shell (npm)
- **Detect:** lockfile shows `next@15.x–16.0.6` or `react-server-dom-*@19.0.0|19.1.0|19.1.1|19.2.0`.
- **Verify:** confirm the App Router / Server Function surface is actually in use
  (`app/` directory, `server actions`, `self.__next_f` in the served HTML) — a Pages-Router
  app on a vulnerable `next` is exposed only if it renders RSC payloads.
- **Prove:** **the version match against the advisory is the evidence — no exploit is
  ever sent.** In-the-wild single-request RCE exists (145+ public PoCs, WAF-bypass
  variants, malware campaigns since Dec 2025); reproducing it is out of Phase 0 scope.
  Mark the finding `critical`, note `KEV` if the local cache lists it, and prove *reachability*
  instead: does an unauthenticated request reach a Server Function/RSC route at all?
- **Impact:** full pre-auth RCE on the app server — the highest-severity class in this repo.

### CVE-2025-29927 — middleware auth bypass (the one lane with a harmless probe)
- **Detect:** `next` below the per-branch floor from a lockfile pin.
- **Verify:** `--live` — the probe GETs up to 4 candidate protected paths twice:
  plain, then with `x-middleware-subrequest: middleware` (and the 5×-nested variant).
- **Prove:** status flip `401/403/302/303/307/308 → 2xx` under the spoofed header =
  **bypass-confirmed** (finding `high`, evidence carries both statuses). A `404 → 2xx`
  flip is a weaker indicator (the path only exists under the spoof). No flip =
  pass `--path` for a route recon knows is gated — the default candidates may all 404.
- **Impact:** every middleware-enforced control (auth, rewrites, geo gates) is
  decorative; pair with 03b for what that unlocks.

### CVE-2026-109618 / 109619 — PHP2Shell
- **Detect:** PHP pin < 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 from Dockerfile,
  `.php-version`, composer platform, or `X-Powered-By` on `--live`.
- **Verify:** deployed version via the runtime's own banner/health endpoint if exposed;
  distro packages may be backported — check the vendor changelog before reporting.
- **Prove:** no exploit sent (unauth RCE class, CISA alert 2026-10-21). Version match
  + reachable unauthenticated PHP endpoint = the finding; EOL branches (≤8.1) are
  findings on *unfixability* too — no patch exists, the fix is an upgrade.
- **Impact:** pre-auth RCE; note `kev` from the local cache.

### CVE-2026-48489 — Symfony firewall bypass · CVE-2026-39976 — Passport identity mix-up · CVE-2026-24425 — Twig sandbox escape
- **Detect:** composer lockfile pin below the fixed version (table above).
- **Verify:** for Symfony — a route behind an `access_control` firewall reachable
  unauthenticated when `failure_forward` is configured; for Passport — a
  `client_credentials` token that resolves user-scoped resources; for Twig — an app
  that sandboxes untrusted template input (`sandbox` policy + user-controlled source).
- **Prove:** version match + the configuration preconditions present in source
  (`failure_forward` in `security.yaml`, sandbox usage in Twig calls). No exploit sent.
- **Impact:** unauthenticated route access / machine→human identity confusion /
  sandbox escape to template-engine code execution.

## Probe bounds (Phase 0 — hard limits in the script)

| Bound | Value |
|---|---|
| HTTP request starts | ≤13 (1 fingerprint + ≤4 paths × ≤3 variants, redirects followed within count) |
| Per-request timeout | 3 s · total HTTP budget 30 s |
| Candidate paths | ≤4 (`--path` overrides; defaults `/admin /dashboard /account /settings`) |
| Targets | loopback only — non-`localhost` `--live` exits `3` before any socket opens |
| Payloads | plain GETs + one well-known bypass **header**; no exploit bodies, ever |

## Watchlist (tracked in-repo, deliberately NOT tool rows)

Fixed ranges below are unsourced or second-hand — they belong in the engagement's
manual verification checklist, not the automated table (a wrong range produces
confident false positives):

- **CVE-2025-55180 / CVE-2025-55181** — Next.js cache-poisoning/auth-bypass cluster
  from Dec 2025; verify against the vendor advisory before trusting any range.
- **CVE-2026-73683** — Laravel Socialite replay; **CVE-2026-49215** — Symfony UX
  LiveComponent CSRF bypass (Accept-header safelisting); **CVE-2026-82329** —
  Artifactory auth bypass; WHD unauthenticated-SAML→admin.
- Rule of thumb: when a fresh CVE lands (this table was written with PHP2Shell *4 days*
  old), pull the vendor advisory first — ranges in blog posts drift within days.

## Reporting

Findings enter `findings.json` as `status: candidate` like every other lane — the
agent must verify before reporting (deployed-version check, reachability of the
affected surface). Enrichment: `score.mjs` reads `cvss_score` (reported) and the
merge-time KEV pass sets `kev: true` from `~/.cache/mr-robot/kev.json` (7-day TTL,
cache-only — no network).

## References

- React2Shell: `nextjs.org/blog/CVE-2025-66478` · `react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components` · Trend Micro in-the-wild analysis (2025-12-10)
- CVE-2025-29927: `nextjs.org/blog/CVE-2025-29927` (floors + `x-middleware-subrequest` mechanics)
- PHP2Shell: CISA alert 2026-10-21 · Qualys / watchtowr / Google Cloud response guides
- Symfony: `symfony.com/blog/cve-2026-48489-security-firewall-bypass-via-failure-forward-subrequest`
- Twig: `symfony.com/blog/CVE-2026-24425-possible-sandbox-bypass-when-using-a-source-policy`
- Related lanes: 03d (supply-chain implants), 03b (what a bypassed gateway exposes), 07 (KEV/SARIF export)
