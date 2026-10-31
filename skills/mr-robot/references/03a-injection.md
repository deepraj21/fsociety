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

## Expression-language injection & JNDI — the Java-stack expression class (CWE-917/74)

SSTI's siblings on the JVM: an *expression language* evaluates attacker input
directly — no template file needed — and JNDI turns an evaluated string into a
fetch that has historically been the RCE step (Log4Shell class). Detect them
**before** guessing SSTI, since the probes and the fixes differ.

- **EL injection — SpEL / OGNL / MVEL / JSP EL (CWE-917):**
  - **Detect:** Spring `@Value("#{...}")`/`SpelExpressionParser.parseExpression(`
    on request data, Struts OGNL (`%{}`, `${}` in struts tags, value stack from
    params), MVEL `Mvel.eval(`, JSP `${param.x}`/`#{}` in unguarded contexts,
    Thymeleaf `th:utext` with expression pre-processing (`__${...}__`), Actuator/
    Spring Cloud Function routing (`spring.cloud.function.routing-expression`) —
    famous sinks where the *whole* expression comes from the request.
  - **Prove (marker-grade, ≤4 requests):** arithmetic marker first —
    `#{7*7}` / `${7*7}` / `%{7*7}` → `49` in the response or its error; then
    stop, or one harmless command-equivalent for the engine's known safe
    primitive (SpEL `T(java.lang.Runtime)` chain is **not** run — the arithmetic
    proof + engine fingerprint is the finding, same RCE-unproven rule as SSTI).
    Error-based when output is swallowed: force the evaluation result into the
    exception (03a SSTI error-based recipe applies verbatim).
  - **Impact:** expression eval = RCE-grade *potential* (`rce-chain` candidate);
    severity = engine + context (function-routing sinks are the wild-RCE CVEs).
    Fix: never parse expressions from input, literal-only templates (06).
- **JNDI / LDAP injection + Log4Shell class (CWE-74/917):**
  - **Detect:** `InitialContext.lookup(user_input)`, `ctx.lookup(` with string
    concat, `${jndi:` / `${ctx:` / `${env:` / `${lower:` lookup patterns in
    **logging** paths (log4j2 `MessagePatternConverter` pre-2.17, logback
    `insertToLookup`, log4j 1.x JMSAppender), JNDI references in config, any
    `java:`/`ldap:`/`rmi:`/`dns:` URL from request data.
  - **Prove (bounded, zero-egress):** never point a lookup at an external host.
    Start a **local listener** (`nc -l 8081` on loopback) and — only if the app
    itself performs a JNDI lookup on attacker input — pass
    `ldap://127.0.0.1:8081/mr-robot-poc` as the marker URL; arrival of the
    lookup (connection bytes at your listener) proves the injection channel.
    For the *log-corruption* variant, write the marker `${jndi:ldap://127.0.0.1:8081/poc}`
    into one field you own (username/search) and observe the app's log triggering
    the local lookup — ≤2 probes, one listener, closed after. **No remote class
    loading, no serialized gadget return, no jar hosting** — connection arrival
    is the whole proof; version rows (fixed ranges) belong to [03n](03n-known-cves.md)
    watchlist discipline if a version match also exists.
  - **Impact:** unauthenticated log-triggered lookup = potential RCE (CVE-2021-44228
    class) → `rce-chain` candidate, NO-GO when confirmed reachable; auth-path
    injection → same lane. Fix: upgrade/disable message lookups, egress filtering
    as defense-in-depth (06).

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

## CSP bypass & payload delivery — getting the payload past the defense (CWE-1021 · WSTG-CLNT-01)

XSS with no CSP is a solved problem — modern apps ship a policy, so the finding
*proves itself* by surviving one. 03b checks CSP **presence**; this is the bypass
discipline that turns "CSP blocks it" into "CSP does not block it":

- **Detect (source):** the policy itself (`Content-Security-Policy` header,
  `<meta http-equiv>`, framework defaults — Django `CSP_`, Helmet, Rails
  `content_security_policy`), nonces/hashes on script tags, `report-uri`/
  `report-to` endpoints, `TrustedTypes` sinks, JSONP endpoints, `<base>` in pages
  whose relative script/asset URLs the attacker can influence.
- **Bypass lanes (bounded, ≤6 requests per lane, marker payloads):**
  1. **Nonce/hash weaknesses:** nonce echoed into the page (reflected nonce =
     policy forfeited), nonce *reuse* across responses (prime → reuse), hash
     allowing a gadget inline (`'sha256-…'` matching attacker-reachable inline).
  2. **`strict-dynamic` gadget chain:** when `strict-dynamic` is on, a *allowed*
     script that passes attacker data to a sink (`innerHTML`, `location`,
     `JSON.parse`→merge) is the bypass — probe the reflected marker through that
     sink; the policy itself allows the chain it enables.
  3. **JSONP gadget:** a JSONP endpoint under the CSP's allowed script origins
     (`'self'` + JSONP host) serving `?callback=<marker>` — `<script src=…>` with
     attacker callback executes under the policy. Pair with JSONP theft below.
  4. **Base-tag / relative-URL hijack:** inject `<base href="http://127.0.0.1:OTHER/">`
     (marker port) into a page with relative `<script src=…>`/`<img>` — the
     browser resolves assets to the attacker origin *within* the policy.
  5. **Report-only downgrade:** `Content-Security-Policy-Report-Only` on a
     sensitive page = no enforcement, only telemetry — record as config finding
     (A05) even without a working bypass.
  6. **JSONP/CORS data theft (no XSS needed):** a JSONP endpoint with reflected
     callback reads authenticated JSON cross-origin from *your* page — ≤4 probes
     with `callback=mr-robot-poc`; impact = credential-data theft, `authz-bypass`
     when the data is another user's.
- **HTML smuggling (delivery, not execution):** stored/reflected *content* that the
  browser turns into a file the user opens — `data:`/Blob download links, `<a
  download>` with a JS-generated payload, HTML-in-HTML (`<iframe srcdoc>`). Prove
  with a marker-named download (`mr-robot-poc.html` content carries `mr-robot-poc`)
  on your own record only; impact lands at the *endpoint* (payload past
  gateways/scanners into the opening user — a delivery channel for the payload
  above, not a new code-execution bug).
- **CSS injection → attribute-selector exfil (the injection half of 03o):** when
  `<style>`/attribute injection exists without script, `input[value^=a]`-style
  attribute selectors + a `background:url(...)` per guess exfiltrate secrets
  (CSRF tokens, inputs) one character at a time — the *same oracle bit* 03o
  models cross-origin, but here the attacker's CSS sits in the page. Prove
  **locally and bounded**: one marker value, ≤2 selector chars, one request to
  your loopback listener — demonstrate the channel, never a real value sweep.
  Report severity via what the value protects (token → `csrf`/`auth-bypass` chain).
- **Bounds:** ≤6 requests per bypass lane, one lane at a time, marker payloads
  (`mr-robot-poc`) only, loopback listener for any exfil callback; every lane is
  `candidate` until the payload demonstrably executes/reads under the policy.
- **Impact/fix:** bypass → same tags as the underlying XSS/JSONP theft;
  remediation = nonce-per-response, drop `unsafe-inline`/`unsafe-eval`, restrict
  script-src to hashed/nonced only, `require-trusted-types-for` — [06](06-remediation.md).

## DOM clobbering & postMessage / iframe sandbox (CWE-1321-adjacent · CWE-346 · WSTG-CLNT-01)

Browser-side logic bugs where the *page's own structure* becomes the attack input —
no script payload ever fires, so XSS filters see nothing.

### DOM clobbering — markup names overwrite JS globals

Anchors/`<form>`/`<img name=…>` in attacker-influenced HTML (comments, markdown,
stored bio, URL fragments parsed into DOM) *shadow* globals the page's scripts read:
`document.cookie` → an HTMLFormElement, `window.config` → an anchor, `auth`/`csrf`/
`isAdmin` clobbered into truthy elements, `formAction`/`action` hijack of login forms.

- **Detect (source):** scripts reading globals that markup can define — bare
  `config`, `auth`, `csrf`, `window.x` where `x` matches any `name=`/`id=` in
  reachable HTML; sinks like `el.innerHTML` fed to *checks* (not just rendering);
  libraries reading `document.cookie`/`location` through clobberable wrappers
  (older jQuery `$.ajax` `url`, DOMPurify bypass chains via named anchors).
- **Prove (marker-grade, own page/test account only):** inject
  `<img name="clobberTarget" mr-robot-poc>` (or a bio/comment containing it) into
  content *you* control; show the page's script now reads the element instead of
  the intended value (devtools trace or a visible behavior flip — e.g. a check that
  failed now passes, a URL that resolved now points elsewhere). ≤4 injections,
  one clobbered name each, no persistence outside your own record — clean up after.
- **Impact:** auth/CSRF-check bypass, gadget for XSS chains (a clobbered `innerHTML`
  sink), config confusion → `auth-bypass` when the clobbered value gates access.
  Fix: `Object.freeze`/namespace checks, `hasOwnProperty`, never trust bare globals
  in markup-reachable scopes ([06](06-remediation.md)).

### postMessage & iframe sandbox — the cross-origin door

`postMessage(data, '*')` with no origin allowlist on receive, or an iframe lacking
`sandbox`/`allow` restrictions, turns any page the victim visits (or any open
redirect — [03c](03c-ssrf-access-file.md)) into a script that can *talk to* the app.

- **Detect (source):** `postMessage(` calls with `'*'` targetOrigin; `message`
  listeners that never check `event.origin` (or check it after acting); iframes
  built without `sandbox`, or with `sandbox="allow-scripts allow-same-origin"`
  (the combo that defeats the sandbox); `contentWindow` access from attacker-writable
  frames; `onmessage` handlers acting on `event.data` fields (tokens, actions).
- **Prove (bounded, local two-origin):** page A at `127.0.0.1:OTHER_PORT` embeds
  the target origin in an iframe and posts `{type:'mr-robot-poc'}`; observe whether
  the target's handler *acts* (response received, action visible) despite the
  foreign origin = confirmed. ≤4 messages, marker payload only, one run — this is
  the same two-origin loopback recipe as [03o](03o-xs-leaks.md) but for *actions*,
  not oracles.
- **Impact:** cross-origin CSRF-grade actions, token/session leakage into the
  message, sandbox escape → stored XSS grade when scripts run in the parent.
  `tags: csrf`/`xss` by what the handler actually does; fix = origin allowlist +
  strict sandbox ([06](06-remediation.md)).

## Deserialization — CWE-502 (WSTG-INJT-23) · MITRE #15

- **Detect:** `pickle.loads`/`load(`, `yaml.load` (no SafeLoader), `unserialize(`,
  `ObjectInputStream`, `JSON.parse` + prototype merge, `marshal.loads`, `php://` phar.
- **Verify:** does attacker-controlled data (cookie, file, queue message) reach it?
- **Prove:** a `__reduce__`/gadget that runs `echo mr-robot-poc`-equivalent (print marker)
  — never a reverse shell; the payload's *existence* + marker output proves RCE.
- **Java gadget chains:** on `ObjectInputStream`/XStream/Jackson-databind
  (`enableDefaultTyping`)/Hibernate/Hessian sinks, the payload is a *gadget
  chain* (`ysoserial`-style) — detect the vulnerable gadget library versions in
  the dependency tree first (commons-collections ≤3.2.1, spring-beans, etc. →
  pair with [03n](03n-known-cves.md)); prove the same way as the reduce above —
  a marker-printing chain (`echo mr-robot-poc`), run once against a localhost
  target, never a reverse shell. XStream/Jackson type-typing acceptance itself
  (any-type deserialization) is already a finding without firing a gadget.

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
- **HTML injection** (CWE-79-adjacent, WSTG-CLNT-01): input rendered as *markup but
  never as script* — `<b>`, `<img src=…>`, `<a href=…>` in comments/bios/search-echo
  where escaping is partial (tags stripped but attributes survive, or a tag allowlist
  lets `<img>`/`<a>` through). No JS execution = not XSS, but stored defacement,
  credential-phishing overlays (`<form>` over the real login), and click-hijack
  links remain. **Prove:** `<mr-robot-poc>` (a non-HTML tag) or
  `<a href="https://mr-robot-poc.example">x</a>` rendered *verbatim* in stored/
  reflected output = the class; the XSS line in the same catalog is what it
  escalates to when a script sink also exists. ≤4 probes, marker values only.

## Chaining ideas (Phase 3)

info-leak → SSRF → metadata creds (03c) · XSS → session/CSRF (03b) ·
upload webshell (03c) → RCE tag `rce` (NO-GO) · SSTI → RCE ·
NoSQLi → auth bypass tag `auth-bypass`.
