# 03c — SSRF, path traversal & file upload (A01:2025 · WSTG-INPV/ATHZ-01 · MITRE #6, #12, #22)

## SSRF — CWE-918 (MITRE #22, API7)

Where the server fetches a URL/resource the user influences: webhooks, `?url=`, image
importers, PDF/report generators, PDF/URL previewers, `requests.get(user_url)`,
`fetch`, axios, `HttpClient.get`, link unfurling, XML external entities.

- **Detect:** opengrep/semgrep `requests.get($URL…`, `urllib.request.urlopen(`,
  `axios.get($X`, `fetch($X`, `http.get(` where `$URL` derives from request data; grep
  `url=` / `href=` / `webhook` in handlers.
- **Verify:** any allowlist/scheme check/DNS-rebinding defense between input and fetch?
  Is the fetch target resolved *after* validation?
- **Prove (localhost only):**
  1. `curl "http://localhost:PORT/fetch?url=http://127.0.0.1:PORT/admin"` → internal
     admin page contents returned to you = classic SSRF (**high**).
  2. Cloud metadata (only if the local stack simulates it / dev container):
     `url=http://169.254.169.254/latest/meta-data/` → credential exposure = **critical**.
  3. Blind SSRF: point at a webhook/request-bin you control *or* a local listener you
     started (`nc -l 8081`) — arrival of the request proves the vector.
- **Bypass tricks to try:** `127.0.0.1` vs `localhost` vs `0.0.0.0` vs `[::1]` vs
  `2130706433`(decimal) vs `0x7f000001` vs `127.1`; `@` confusion (`evil.com@127.0.0.1`);
  DNS rebinding; redirect to metadata after allowlisted domain; `file:///etc/passwd`;
  scheme mix (`gopher://`, `dict://`).
- **Blind → visible with redirect loops (Top-10 #3):** a fetcher that follows
  redirects leaks *how far it got* when you hand it a loop you control:
  - **Probe (bounded, localhost):** start a local redirector on loopback
    (`/r?n=N` → `302 Location: /r?n=N+1`, counter in the path) and pass it as the
    fetch target. The client's final error distinguishes graded states no blind
    boolean can: *connection refused* (never left the validation stage) vs
    *too many redirects* after N hops (reached and followed you — and N reveals
    the client's redirect budget) vs a marker arriving at your listener (full
    visibility). Pair with the allowlist-bypass redirect above to learn *which*
    hop the validation stopped at.
  - **Bounds:** one chain, ≤10 hops, one probe run, redirector on 127.0.0.1 only —
    never a chain that leaves your machine (zero-egress rule).
  - **Impact:** turns `ssrf: blind` into `ssrf: confirmed/reachability-graded`,
    and the graded oracle is reportable evidence in its own right.
- **Impact check:** which gateways does SSRF cross? (metadata → cloud creds; internal
  admin → auth bypass; port scan → recon). Chains get `tags: ssrf` + the end-state tag.

## Path traversal / LFI / RFI — CWE-22 (MITRE #6, WSTG-ATHZ-01, INPV-11)

- **Detect:** `open(base + user)`, `path.join(root, req…)`, `send_file(req.query.file)`,
  `fs.readFile(…)`, `include(req…)`, `File(…)`, `readfile(` with request data; static
  file servers with `..` in URL decode order issues.
- **Verify:** normalization happens *after* concatenation? Blacklist (`.`, `/`) instead of
  resolved-path-prefix check (`realpath(p).startsWith(root)`)? Double-URL-encoding,
  null bytes (`%00`), Windows `..\` vs `/`.
- **Prove:** `GET /download?file=../../../../etc/passwd` → root:x:0:0 visible (**high**);
  app-specific marker: read a file outside root you know exists. LFI→RCE chains (log
  poisoning, phar, session-file include) → `tags: rce`.
- **Sensitive-file check:** can it read `.env`, `.git/`, cloud creds, `/proc/self/environ`?

## Unrestricted file upload — CWE-434 (MITRE #12, WSTG-BUSL-08/09)

- **Detect:** upload handlers: `multer`, `request.files`, `django.core.files`,
  `werkzeug.datastructures.FileStorage`; check: extension allowlist? content-type trust?
  server-side re-encode? storage outside webroot? filename from user (path traversal via
  `../../` in filename — combines with traversal above)?
- **Prove (harmless):**
  1. upload `shell.jpg.php` / `shell.php.jpg` / `.phtml` / double extension → if served
     **and executed** → webshell risk = `tags: rce` (**critical** when confirmed).
  2. Prove execution with a *harmless* script (`<?php echo "mr-robot-poc"; ?>`) — never a
     real webshell; then delete the uploaded file and **verify deletion**.
  3. SVG/HTML upload → stored XSS when rendered (cross-link 03a).
  4. Polyglot (valid image + PHP) bypasses content checks.
- **Zip slip — archive extraction traversal (CWE-22):** any handler that *extracts*
  an uploaded archive (zip/tar/jar/war — import bundles, theme/plugin uploads,
  backup restores) and joins entry names onto a target dir without sanitizing
  `../` in the name writes outside the extraction root — overwrite of app code or
  config when the root sits near writable source.
  - **Detect (source):** `zipfile.extractall(` / `ZipFile.extract(` without name
    checks (Python), `adm-zip`/`yauzl`/`unzipper` extract with raw `entryName`,
    Go `archive/zip` + manual path join, Java `ZipInputStream` loops, shell
    `unzip $upload` — anywhere entry names reach `fs`/`path` unsanitized.
  - **Prove (bounded, one archive):** craft a zip whose single entry is named
    `mr-robot-poc-slip/../../<relative-escape>` targeting a **temp dir you own**
    (never app source, never system paths); run the app's own extraction (local
    function call or the upload endpoint once) and show the marker file landed
    *outside* the extraction root. Then delete it and **verify deletion**. One
    archive, one entry, marker filename only.
  - **Impact:** write-near-source → `rce`/`config-tamper` when it can reach code
    or `.env`; `tags: path-traversal`; fix = sanitize entry names, reject `..`
    and absolute names, extract-then-verify containment ([06](06-remediation.md)).

## Open redirect — CWE-601 (WSTG-CLNT-04)

- `?next=https://evil.com`, `//evil.com`, `/\evil.com`, `https://trusted.com.evil.com`.
- Low on its own; chain value: phishing + token theft in OAuth (03b) → elevate to medium.

## Directory listing / backup files (WSTG-CONF-04/05)

- Unreferenced files: `/.git/HEAD`, `/backup.sql`, `app.py.bak`, `/.env`, `/~/.ssh`,
  `/web.config`, `/.DS_Store`, `server.key`. Trivy/gitleaks catch some — grep the repo
  for committed artifacts too (passive).

## Prove discipline

Localhost only; read-only proofs (view content, marker echo); every uploaded test file
deleted + deletion verified; nothing written outside `/tmp/mr-robot-poc-*` (removed).
