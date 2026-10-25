# 01 — Report structure: what each section must answer

`report.mjs` renders the mechanical body of `REPORT.md`; you write the judgment
on top of it. This file is the per-section guide: what each section answers,
what to verify, and where agents usually get it wrong. Structure itself is
fixed (the script numbers the sections) — your job is interpretation, not
reorganization.

## Ground rules

- **Never invent.** Every claim traces to a row in `capture.json`. The capture
  is the audit trail; if you didn't see it there, you can't write it here.
- **No verdict.** romero observes. "Production-ready / not ready" is
  `mr-robot`'s `score.mjs` call — if your observations suggest a real security
  problem (auth bypass shape, injection shape, exposed secret), recommend
  running `mr-robot` against the target instead of grading it yourself.
- **Values stay raw** — the report lives on the operator's machine. Do not
  "helpfully" mask or truncate beyond what the script already does.
- Numbers in §1 must match `capture.counts` — if you hand-edit, recheck.

## Section by section

### 1. Summary
Answers: *what was looked at, how big is the surface, what's the headline?*
Verify counts against capture.json. The one narrative line you may add: which
observation from §12 deserves the operator's attention first.

### 2. Pages & frames
Answers: *which pages actually loaded, and what frames did they pull in?*
Red flags: a frame with an unexpected origin (ad/tracker/iframed embed),
main-frame navigations you didn't plan (redirect surprises — trace them in §3).

### 3. API surface
Answers: *what endpoints does the app expose, and which ones carry auth?*
- Endpoint templates collapse ids — check the raw URLs in capture.json before
  claiming two calls are the same endpoint.
- `auth:` in Notes means an Authorization/API-key header was on the wire —
  confirm which storage origin that credential came from (§8).
- GraphQL rows: the operation name is the *contract*; unauthenticated
  sensitive-sounding operations are worth calling out.
- WS/SSE rows are real-time channels — note if frames carry tokens or PII.

### 4. Request-header inventory
Answers: *what does the browser send about the user?*
Red flags: `Authorization` on many endpoints (token lifetime matters — check
JWT `exp` in §8), `Referer` carrying paths from authenticated pages to
third parties (cross-check §9), client hints / full UA (fingerprinting
surface — factual note, not accusation).

### 5. Response headers & security checklist
Answers: *does the server set the protections modern browsers enforce?*
Read `02-header-cookie-reference.md` before judging a value — e.g. HSTS
without `includeSubDomains` on a bare domain is incomplete, not present;
`X-XSS-Protection: 0` is the *correct* modern value. Count is per same-origin
response: a header on one endpoint but not others is itself a finding-grade
observation (say which endpoints differ).

### 6. Cookies
Answers: *what session material exists, who can read it, where does it go?*
Session cookies without HttpOnly = any XSS reads the session. `document.cookie`
diff vs jar shows exactly what JS can see. Cross-check Set-Cookie events for
cookies set by third-party responses (they land in the jar too).

### 7. Browser storage
Answers: *what does the app persist where the user's browser will keep it?*
localStorage = readable by any script on the origin, forever, unencrypted.
IndexedDB `count` but no sample keys usually means empty stores (the harvest
records counts from cursors — keys sample up to 20). A service worker means
the origin can serve content offline — check its scriptURL is same-origin.

### 8. Tokens & credentials
Answers: *what secrets crossed the wire or rest in the browser?*
- For every JWT: decode says `exp` in the past → stale token still accepted?
  (observational note only — verifying acceptance is mr-robot's active work).
- Storage JWTs are the classic "XSS = account takeover" amplifier — name the
  storage key and origin.
- URL-query secrets leak via history/Referer/logs — always worth surfacing.
- Absence of findings here is meaningful: say so plainly, don't hedge.

### 9. Third-party contacts
Answers: *who else is in the room, and what are they getting?*
`Cookies sent? yes` to a third party is the row operators remember — verify
it isn't a subdomain of the product itself before alarming anyone (host
column is exact). Body fields listed = the third party receives those field
*names* (and values — check capture.json if asked).

### 10. Performance, caching & protocol
Answers: *how fast, how cached, what protocol, any insecure loads?*
Mixed-content rows on an https target are hard failures in browsers — list
all of them. Uncompressed text on big responses is a cost/latency note, not
a security note — keep the categories apart.

### 11. Console, JS errors & security log
Answers: *what did the page complain about while it ran?*
CSP-violation and "Refused to" lines here are the browser *enforcing* policy
(and prove the policy is live); mixed-content warnings corroborate §10.
Console errors that only appear post-login are often broken auth paths —
note where they came from.

### 12. Observations & coverage
Answers: *what should a human look at, and what did this run NOT cover?*
- Observations are heuristic — each must carry its section pointer (the
  script does this; keep the style if you add rows).
- Coverage is a promise: if the run had a budget cut, a load timeout, or
  never visited a flow the operator cares about, it goes here, plainly.
- The closing recommendation pattern: "observations X, Y — worth a
  `mr-robot` run for verdict-grade analysis" or "surface looks clean for
  passive observation; interactive flows still unexercised."

## Common failure modes

1. **Re-running the report without re-capturing** after the app changed —
   the report is point-in-time; stamp your notes with the capture window.
2. **Treating §3 counts as traffic volume** — one SPA load can repeat an
   endpoint; counts are call counts, not unique users.
3. **Skipping §9 because §1 said "no third parties"** — read §9 anyway; a
   same-host different-port service can still be third-party by host string.
4. **Writing recommendations that require attacking** — those go to
   mr-robot, with the URL and the operator's confirmation, not here.
