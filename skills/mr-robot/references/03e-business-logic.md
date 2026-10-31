# 03e — Business logic & API abuse (A06:2025 · WSTG-BUSL · OWASP API Top 10)

Scanners cannot find these — they come from Phase-1 mapping + reasoning about what the
product *does*. Always load for apps with money, quotas, or multi-step flows.

## Core method

For each business flow: write the *intended* sequence → break it.

1. Reorder steps (pay before ship? skip verification?).
2. Repeat steps (reuse a one-time action).
3. Negate/alter amounts, quantities, flags.
4. Race concurrent requests (TOCTOU).
5. Send requests out of band (direct API calls bypassing the UI).

## Flow tests (WSTG-BUSL-01..10)

- **Workflow circumvention** (-06): jump to step 3 without 1–2 (`/api/order/confirm`
  without cart), skip email/ID verification by calling the final endpoint directly.
- **Process timing / race** (-04): concurrent coupon-redemptions / balance transfers /
  double-spend — `scripts/race-probe.sh` sends N identical requests in parallel
  (≤20, localhost-only, compares responses for divergence) and checks whether the
  invariant held. One extra success = confirmed (high if money/stock).
- **Function-call limits** (-05): Nth-use restrictions (1 free export/month) enforced
  only client-side → call the API directly past the cap.
- **Integrity checks** (-03): client-supplied totals/discounts/signatures
  (`total` in request body trusted?), unsigned price fields.
- **Misuse defenses** (-07): CAPTCHA/bot checks bypassable via API; identical automation
  not rate-limited (cross-link 03b rate-limit).
- **Unexpected uploads** (-08/09): → 03c.
- **Payment functionality** (-10): negative amounts, `0`, `0.01` vs `100`, currency
  confusion (`amount=100` cents vs units), webhook signature not verified (Stripe/ PayPal
  `verify_signature` skipped → forge `payment_succeeded`), replayed webhook, refund > charge.

## ORM / search-filter data leaks (Top-10 #2 — "more than you joined for")

As SQLi-as-dumping-tooling fades, the *legitimate* query layer becomes the leak:
ORM search/filter/sort APIs let the caller ask for more than the UI ever shows —
nested includes, relation traversal, operators the interface never emits.

- **Detect:** list/search endpoints driven by ORM query builders — `?include=`,
  `?expand=`, `?with=` (Django `select_related`/`filter` lookups, Rails `includes`,
  Prisma `include`, Eloquent `with`), `$filter`/`$expand`/`$select` (OData),
  sort/filter params hitting relation columns, GraphQL selection sets (→ 03j).
- **Probe (bounded, own/fixture rows):**
  1. **over-fetch:** request a nested relation the UI never renders
     (`include=roles`, `expand=owner.address`, `fields=users.password`) → if it
     serializes back, the join leaked;
  2. **error-guided schema recovery:** malformed include/sort/filter
     (`include=notacolumn`, `sort=secret.$desc`) → verbose ORM/SQL errors map
     tables and column names (feed the result to 01 recon);
  3. **filter-operator extraction:** operators beyond the UI's equality
     (`role__ne=`, `email__contains=`, `id__gt=`) on relation fields → boolean or
     ordered extraction through filters the interface can't express; if responses
     are uniform, run it as a timing/error oracle per [03o](03o-xs-leaks.md).
- **Bounds:** ≤12 requests per endpoint; read *your own* fixture rows to prove the
  class — touching another user's row via an operator proves impact in ONE bit,
  then stop (no bulk enumeration; that's 03b BOLA territory with data exfil).
- **Impact:** sensitive-column disclosure (PII, roles, tokens, password hashes)
  → high; relation traversal skipping ownership = `api-bola`/`authz-bypass`
  (→ [03b](03b-auth-gateway.md) §3); schema errors → recon. Fix: serializer-level
  field allowlists, no operator passthrough, per-object authorization (06).

## API Top 10 cross-check (OWASP API1–10:2023)

| ID | Test | Where |
|---|---|---|
| API1 BOLA | object id in path/body without ownership check | 03b §3 horizontal |
| API2 Broken auth | JWT/session flaws, no lockout | 03b §1–2 |
| API3 BOPLA | response over-exposure (`password_hash`, `ssn` in JSON) **and** mass assignment (`role: admin` accepted) | below |
| API4 Resource consumption | no pagination/limits, unbounded `?limit=`, zip bombs, file size | below |
| API5 BFLA | admin function callable by normal role | 03b §3 vertical |
| API6 Business flows | automation of sensitive flows (ticket sniping, signups) | above |
| API7 SSRF | webhook/URL params | 03c |
| API8 Misconfig | verbose errors, debug routes, permissive CORS | 03g |
| API9 Inventory | undocumented/shadow/old-version endpoints (`/v1`, `/graphql` in prod, `/debug`) | 01-recon |
| API10 Unsafe consumption | trusts 3rd-party API responses (validate inbound webhooks/payloads!) | below |

**BOPLA checks:** fetch an object as a normal user → any sensitive property in the JSON?
(`grep` serializers: `exclude`/`only` fields — Django DRF, NestJS DTOs, `toJSON`).
Then mass-assign: send `{"role":"admin","verified":true,"balance":9999}` at an update
endpoint → accepted? (→ usually `authz` blocker chain).

**Unsafe consumption:** inbound webhook handler trusting payload without signature =
forged domain events; third-party API response used as authorization data.

## GraphQL specifics (WSTG-APIT-99)

- Introspection enabled in production? Depth-limited queries? Batching to bypass rate
  limits? Field-level authz (can user query `_user { email }` on someone else's node)?
  `__schema`/`__type` exposure; N+1 as an info-leak timing side channel.

## Output discipline

Each confirmed issue: flow broken → exact request sequence → invariant violated →
impact (money/data/abuse volume) → server-side enforcement fix (never "hide the button").
Tag money/stock/auth-impact findings appropriately — payment tampering + authz bypass are
NO-GO blockers when confirmed.
