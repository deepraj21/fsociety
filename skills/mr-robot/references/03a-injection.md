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

## Prototype pollution — CWE-1321 (WSTG-INJT-22)

- **Detect:** recursive merges without key filtering: `_.merge/defaultsDeep`,
  `Object.assign(target, JSON.parse(body))`, `extend(`, `clone(` with `__proto__` gaps.
- **Prove:** `{"__proto__":{"mr-robot-poc":1}}` → observe polluted property on `{}`/config flag.

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
