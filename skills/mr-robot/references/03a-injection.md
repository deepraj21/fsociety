# 03a — Injection catalog (OWASP A05:2025 · CWE Top 25 #1, #2, #9, #10)

Per class: **Detect** (tooling) → **Verify** (source trace you must confirm) →
**Prove** (harmless localhost PoC). Confirm a real attacker-reachable source→sink
before recording `status: confirmed`.

## SQL injection — CWE-89 (WSTG-INJT-05)

- **Detect:** opengrep `p/security-audit`, local rule `mr-robot-py-sqli-concat-execute`,
  bandit `B608`, grep sinks: `execute(`, `.raw(`, `text(f"`, `$query\{`, `format(` with
  SELECT/INSERT/UPDATE/DELETE, `WHERE $1` missing (string concat).
- **Verify:** trace the input (route param/body/query) → does any validation/parameterization
  sit between? ORM "safe" calls still fail on `text()`/`raw()`/f-string table names.
- **Prove (local):** find a reflected param and prove the *mechanism* only:
  ```
  curl -s "http://localhost:PORT/item?id=1'"        # → SQL error / changed behavior
  curl -s "http://localhost:PORT/item?id=1 AND 1=1"  # → normal
  curl -s "http://localhost:PORT/item?id=1 AND 1=2"  # → different → blind SQLi
  ```
  `sqlmap --batch --level 1 --risk 1 --technique T --threads 1 -u "<url>"` is acceptable
  **only** against the local DB — stop as soon as mechanism is proven; never dump rows.
- **Variants:** error-based, boolean-blind, time-blind (`AND SLEEP(3)`), union-based,
  second-order (stored value later interpolated), ORM raw escapes, table/column-name
  interpolation, **NoSQLi** (`{"$gt": ""}`, `$where` JS in Mongo), GraphQL dataloader args.

## OS command injection — CWE-78 (WSTG-INJT-12)

- **Detect:** `os.system(`, `subprocess.*(shell=True`, `exec(`, `child_process.exec`,
  backticks/`$( )` with variables, `Runtime.getRuntime().exec`, `popen(`.
- **Verify:** can user input reach the command string without a strict allowlist/`shlex.quote`?
- **Prove:** payload `; echo mr-robot-poc` or `| echo mr-robot-poc` → marker in response.
  Never run destructive commands; marker only.

## Code injection / eval — CWE-94/95 (WSTG-INJT-11)

- **Detect:** `eval(`, `exec(`, `Function(`, `vm.runInNewContext`, `assert ` misuse,
  `compile(` on user data, template `render_template_string(user_input)`.
- **Prove:** payload proving expression evaluation: `{{7*7}}` → `49` (SSTI) or
  `__import__('os').popen('echo mr-robot-poc').read()` — run only the marker echo.

## Server-Side Template Injection (SSTI) — CWE-1336 (WSTG-INJT-18)

- **Detect:** user input into `render_template_string`, `Template(...)`, Jinja/Twig/Freemarker/
  ERB string concat; `|safe`, `Markup(`, `{{{ }}}` with dynamic content.
- **Prove:** probes in order — `{{7*7}}` → `49`; `${7*7}` → `49`; `<%= 7*7 %>` → `49`;
  then stop at expression proof (or harmless `popen('echo mr-robot-poc')` for Jinja).
- **Error-based blind (output swallowed — the 500 page IS the channel, Top-10 #1):**
  when rendered output never reaches you, force the *evaluation result into an
  exception* and read it back:
  - `{{7*'7'}}` → Jinja/Twig string-repeat (`7777777`) vs engines that error on
    type — the error *shape* fingerprints engine + sink in one shot;
  - `{{'mr-robot-poc'|nonexistentfilter}}` → filter errors often echo the evaluated
    argument — the marker arriving in the traceback proves execution;
  - `${7/0}` / `{{ 1/0 }}` → arithmetic errors leak engine name, file paths, template
    line numbers (also recon for 01).
  - **Prove:** marker visible in a 500 body, error log you can read back, or a
    time-delay expression (`{{ cycler.__init__.__globals__.os.popen('sleep 1').read() }}`
    → *duration* proves execution without output) — ≤2 delay probes, no other commands.
- **Polyglot detection (bounded, ≤8 requests):** chain per-engine markers that
  *differ in behavior* — `{{7*'7'}}` (Jinja/Twig), `${7*7}` (Velocity/Mako-ish),
  `<%= 7*7 %>` (ERB), `#{7*7}` (Freemarker) — one request chain fingerprints both
  the engine and the sink class instead of the classic "SSTI found, engine unknown"
  dead end. Always stop at expression/marker proof — RCE stays unproven by design.

## XSS — CWE-79 (WSTG-INJT-01/02, CLNT-01) — MITRE #1

- **Detect:** reflected: input echoed unescaped in responses; stored: saved then rendered;
  DOM: `innerHTML=`, `document.write(`, `location.hash` sinks, `dangerouslySetInnerHTML`,
  `|safe`, `Markup(`, `HtmlResponse(`.
- **Verify:** framework auto-escaping genuinely covers the spot (templates ≠ JSON APIs ≠
  `innerHTML` sinks — escaping does not apply to JS-string/URL contexts).
- **Prove:** `"><script>/*mr-robot-poc*/</script>` reflected verbatim → reflected XSS;
  for DOM: show the sink evaluates attacker-controlled `location` data.

## Deserialization — CWE-502 (WSTG-INJT-23) · MITRE #15

- **Detect:** `pickle.loads`/`load(`, `yaml.load` (no SafeLoader), `unserialize(`,
  `ObjectInputStream`, `JSON.parse` + prototype merge, `marshal.loads`, `php://` phar.
- **Verify:** does attacker-controlled data (cookie, file, queue message) reach it?
- **Prove:** a `__reduce__`/gadget that runs `echo mr-robot-poc`-equivalent (print marker)
  — never a reverse shell; the payload's *existence* + marker output proves RCE.

## XML external entities (XXE) — CWE-611 (WSTG-INJT-19)

Any endpoint parsing XML/SOAP/SVG/XLSX/parsers-with-DTD: `ElementTree` (pre-3.8
`resolve_entities`), `lxml.etree.fromstring` (no `resolve_entities=False`),
`libxml2`, `DocumentBuilder`, JAXB, `XMLInputFactory`, PHP `simplexml_load_*`.

- **Detect:** XML parsers fed request bodies/params; SOAP routes; SVG/XLSX upload
  parsed server-side; DTD/DOCTYPE in fixtures or sample XML in the repo.
- **Verify:** does the parser resolve external entities / DTDs by default? Older
  lxml (<2.3), Python (<3.7.1), and any explicitly `resolve_entities=True` are live.
- **Prove (harmless, local only):**
  1. **In-band entity:** DOCTYPE entity `&xxe;` defined as `mr-robot-poc` → echoed
     in the response = parser resolves entities (**medium**; the mechanism is the
     whole finding).
  2. **File read:** entity → `file:///etc/passwd` (or repo-local marker file) →
     contents in response = **high** (LFI-grade, CWE-22 chain).
  3. **Blind/OOB:** parameter entity + external DTD fetched from a *local* listener
     (`nc -l 8081`) you started — arrival of the fetch proves blind XXE; never point
     OOB at an external host (zero-egress rule + Phase 0).
  4. **Billion laughs (bounded!):** one nested-entity expansion sized to prove
     quadratic growth (small, e.g. 5 levels × 10) — kill the request at first sign
     of lag; report DoS potential without running a real bomb.
- **Variants:** XInclude (`xi:include`), XSLT stylesheet injection (SSTI-adjacent,
  cross-link above), SVG `xlink:href` fetches (SSRF cross-link 03c).

### SOAP/WSDL attack surface — the generated-client class (Top-10 #5, SOAPwn)

Beyond XXE-*in* SOAP: frameworks that build HTTP client proxies *from fetched WSDL*
turn attacker-shaped metadata into code the server then runs (.NET
`HttpWebClientProtocol` lineage — one unfixed Microsoft flaw became an RCE sink
across products, per watchtowr's whitepaper). Endpoint URLs, serializers, and
bindings all come from the WSDL — the proxy is the parser *and* the client.

- **Detect:** generated proxies in-repo (`svcutil`/`wsdl.exe` output, `.svcReference`,
  `ServiceModel`, JAX-WS `@WebServiceRef`, PHP `SoapClient(` with `stream_context`),
  server-side fetches of `?wsdl=` URLs, import-WSDL build steps, legacy `.asmx`/
  `.svc` routes.
- **Prove (marker-grade, localhost):** serve a *harmless* WSDL from loopback whose
  service/operation names carry `mr-robot-poc`, point any in-scope "import WSDL"
  path at it, and show the marker arriving in generated endpoint URLs, build logs,
  or runtime error messages — that reflection *is* the proof the proxy consumes
  attacker WSDL. ≤5 requests; no malicious operations, no payload bindings — if no
  WSDL-import feature exists in scope, record surface availability only.
- **Impact:** the WSDL fetch itself is SSRF (→ [03c](03c-ssrf-access-file.md));
  DTDs inside WSDL are XXE (above); attacker-chosen operation endpoints = request
  routing to internal URLs, worst case serializer/gadget chains → `rce-chain`
  candidate. Advisory rows belong in [03n](03n-known-cves.md)'s *watchlist*
  discipline — ranges only from the vendor advisory.

## Prototype pollution — CWE-1321 (WSTG-INJT-22)

- **Detect:** recursive merges without key filtering: `_.merge/defaultsDeep`,
  `Object.assign(target, JSON.parse(body))`, `extend(`, `clone(` with `__proto__` gaps.
- **Prove:** `{"__proto__":{"mr-robot-poc":1}}` → observe polluted property on `{}`/config flag.

### Polluted → RCE: gadget hunting (why PP is critical, not medium)

Pollution alone is property injection; it becomes RCE when a **gadget** — a
dependency that reads attacker-influenceable keys off an object — *executes* what
it reads. React2Shell (CVE-2025-55182, [03n](03n-known-cves.md)) is the 2025
poster: a duck-typed `$1:then:constructor` chain routes Flight deserialization
into `Function`. The generic hunt, before any live probe:

- **Detect (deps, passive):** grep installed packages for gadgets that read
  dangerous keys from merged options:
  ```
  grep -rlE "outputFunctionName|escapeFunction|compileDebug" node_modules/*/lib 2>/dev/null | head   # ejs/pug template option RCE
  grep -rlE "child_process|execSync" node_modules/*/index.js 2>/dev/null | grep -i "option\|opts" | head
  grep -rlE "allowProtoPropertiesByDefault|allowProtoMethodsByDefault" node_modules/ 2>/dev/null | head  # handlebars gates
  ```
  Prime suspects: `ejs`/`pug`/`handlebars` view options fed from merged config,
  `child_process` wrappers taking `options.shell`/`env` from an options object,
  `socket.io`/`body-parser` recursive merges, `lodash.template` options,
  anything doing `require(x)` where `x` came off a polluted object.
- **Verify:** is the merge reachable pre-auth (JSON body → `merge(config, req.body)`)?
  Pollution via **both** `__proto__` and `constructor.prototype` (many filters block
  only the first); note which key path worked — it belongs in the evidence.
- **Prove (marker-grade — the pipe, not the payload):** drive the same chain with
  a benign value: pollute the gadget's option key with the marker string and show
  it arriving at the sink (rendered into output, echoed in logs, visible in the
  constructed command line). That proves control; the weaponized step — swapping
  the marker for an exec payload — is exactly what we do NOT take. Report
  `critical` with the full chain (`merge sink → gadget → sink`) as evidence.
- **Impact:** unauthenticated JSON body → property pollution → gadget = RCE
  (A03/A08 chain); tag `rce-chain`, and pair with [03n](03n-known-cves.md) when
  the polluted dependency also carries a known exploited CVE.

## Unicode normalization — when one component translates and another doesn't (CWE-176/179 · WSTG-INJT-04/ATHN-04)

Security decision on raw bytes, application semantics on normalized text (or vice
versa) — the gap is the bug. "Lost in Translation", Top-10 #4: WAF and denylist
regexes run *before* the framework's NFKC pass, so the filter sees something else
than the sink does.

- **Detect:** identity/allow/deny decisions on user strings where stages normalize
  differently — username/email uniqueness, path & extension checks, URL denylists,
  WAF rules over URLs/params; anything regexing `../`, `.php`, `script` on *input*
  bytes. Suspect harder where the stack mixes languages (nginx + app, CDN + origin,
  JS validates + server decides).
- **Bypass families:**
  - **Fullwidth/mixed-width:** `ｓｃｒｉｐｔ`, `．ｐｈｐ` (U+FF01–FF5E) — NFKC → ASCII *after*
    the regex ran; `%ef%bc%8f` → `/` after path checks.
  - **Homoglyph / mixed-script:** `аdmin` (Cyrillic а), `раypаl` — distinct to the
    comparison, identical-looking to the user; also confusable *hostname* twins in
    redirects/callback allowlists (cross-link 03k).
  - **Double/alternate encoding:** `%252e%252e%252f`, overlong UTF-8, `..;/` — each
    decode hop is a potential stage disagreement (cross-link 03i parser rows).
  - **Bidi/zero-width:** RLO/U+202E reversing `exe‮txt` into a filename that *displays*
    as `exe.txt`; ZWSP splitting an otherwise-blocked word past keyword filters.
- **Prove (marker-grade, own identifiers only):** register or resolve an NFKC twin of
  your *own* account/parameter → both land on one record = normalization gap; or
  smuggle a `../`-equivalent into one *harmless* read path carrying `mr-robot-poc`.
  ≤12 requests with a ≤6-pair probe table — no spraying lookalikes at other users'
  identities (that's enumeration, 03b/03o).
- **Impact:** denylist bypass → stored XSS/LFI, twin-identity auth confusion
  (`auth-bypass` tag when it reaches a login/verify), homoglyph callback domains
  → token theft (03k). Fix: normalize **before** compare (NFKC + script-confusable
  fold), `===` on the normalized form (06 has the pattern).

## PHP type juggling — loose comparison bypasses (CWE-697)

PHP's `==` coerces: comparing attacker input against a secret/hash/signature
doesn't mean what the author thinks it means. The oldest PHP-only bypass class —
still live in payment callbacks, legacy auth, and any `md5(...) == $x`.

- **Detect:** `==`/`!=` where `===` was meant (`$_GET['sig'] == $expected`), loose
  compare of *hashes* (`md5($input) == $stored`), `strcmp($input,$secret) == 0`
  (array param → `NULL == 0` → true), `switch`/`in_array`/`array_search` without
  strict flag, truthiness gates on input (`"0"`, `"false"`, `""` are falsy —
  `if (!$token)` skips), `empty()` on user values.
- **Prove (marker-grade, own test accounts only):**
  - **magic hash:** two *known* `0e\d+` strings collide under loose compare
    (`md5('240610708') == md5('QNKCDZO')`) — proving the comparison is loose needs
    no target secret at all;
  - **type confusion:** `?param[]=x` where a string was expected → error/behavior
    shift proves `==`/string-op on an array;
  - **gate proof:** submit the juggling value at the check → accepted where a
    hash/token/amount was verified = the finding (`auth-bypass`, `payment-tamper`
    for money paths, cross-link [03b](03b-auth-gateway.md) §2).
- **Impact:** auth bypass, signature/callback forgery, amount confusion; severity
  = how close the loose compare sits to a trust boundary. Fix: `===`,
  `hash_equals()` for secrets, strict `in_array` — [06](06-remediation.md).

## HTTP-layer injection (WSTG-INJT-03/04/15/16/17)

Deep protocol-level testing (smuggling/desync, cache poisoning, Host attacks,
CRLF, ReDoS) has its own catalog — [03i-http-protocol.md](03i-http-protocol.md).
Quick hits here:

- **Host-header injection:** `Host:` override → password-reset/poisoned links.
- **HTTP parameter pollution:** duplicate params (`?id=1&id=2`) — framework-dependent parsing.
- **Request smuggling / response splitting:** only meaningful behind a proxy — test if the
  repo ships nginx/traefik config with conflicting `Content-Length`/`Transfer-Encoding` handling.
- **CRLF:** `%0d%0aSet-Cookie:` in reflected params/redirects.

## Smaller but real

- **LDAP/XPath/SSI/IMAP injection** (WSTG-INJT-06/07/08/09/10): same pattern — query
  strings built from input in directory/XML/mail queries.
- **CSV/formula injection** (WSTG-INJT-21): exported cells starting `=+@-` → spreadsheet RCE
  surface; prove with `=1+1` cell, no formula that exfiltrates.
- **Format-string** (WSTG-INJT-13): `printf(user_input)` in C/Go.
- **Log injection:** CRLF in logged fields forging audit lines (A09 impact multiplier).

## Chaining ideas (Phase 3)

info-leak → SSRF → metadata creds (03c) · XSS → session/CSRF (03b) ·
upload webshell (03c) → RCE tag `rce` (NO-GO) · SSTI → RCE ·
NoSQLi → auth bypass tag `auth-bypass`.
