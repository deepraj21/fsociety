# 03m — SAML federation (CWE-347/294/611/287 · WSTG-IDNT/ATHN federated SSO)

SAML SSO is XML + signatures + clocks — a different failure surface than OAuth/OIDC
([03k](03k-oauth-oidc.md)). The whole protocol is one signed XML document: if the
service provider (SP) parses before it validates — or validates one node and reads
another — the attacker mints their own identity. **Load this file only when the repo
actually speaks SAML**; otherwise it is dead weight.

**Find it (Phase 1, passive):** `python3-saml` / `onelogin` / `pysaml2`, `ruby-saml`,
`passport-saml` / `saml2-js`, Spring Security SAML / `opensaml`, Keycloak/Dex/ADFS
references in deploy config; grep for `saml:`, `md:EntityDescriptor`, `<sso:`,
`AssertionConsumerService`, `WantAssertionsSigned`, `IdP metadata` XML files.

**Active-phase bounds (Phase 0):** config/code review is always allowed; forging and
replaying assertions happens only against a **local test IdP/SP the user runs**
(the fixture's shape, their dev SSO) with explicit confirmation. The organization's
real IdP (Okta/ADFS/Entra) is a third-party system — review its exported config, never
attack it.

## 1. Unsigned response or assertion accepted — CWE-347

SP signs nothing down: accepts responses with no signature, or signs the *response*
wrapper while the assertion itself is forgeable.

- **Detect:** `WantAssertionsSigned="false"`, missing `WantResponseSignature`, code
  path that reads `Assertion` without calling the signature validator first, validator
  return value ignored (`if not validate(): pass`), `security["wantAssertionsSigned"]`
  unset in python3-saml config.
- **Prove:** forge an assertion (marker NameID `mr-robot-poc@local.test`), send it
  unsigned to the local SP's ACS endpoint — accepted session = the whole authn model
  is decorative. Never use a real user's NameID.

## 2. Signature wrapping (XSW) — CWE-347

The signature still validates (over a *moved or duplicated* assertion), but the app
reads a *different* assertion node than the one that was verified — attacker controls
the identity the app actually uses.

- **Detect:** the SP's parser reads the *first* `<Assertion>` in the document while
  the validator verifies by `ID` reference — or an XPath that an attacker-reordered
  document can satisfy. Look for `doc.getElementsByTagName("Assertion")[0]`-style
  reads decoupled from the validated node.
- **Verify:** exactly one code path from raw XML → session attributes, and it must be
  *the validated node*. Two parses of the same document = the bug.
- **Prove:** wrap a signed (captured own) assertion + a forged second assertion in one
  document; if the session takes the forged NameID while signature validation logged
  "ok", that is XSW — account takeover, NO-GO-class.

## 3. Assertion replay — CWE-294

`AssertionID` / `ID` never cached, no `OneTimeUse` condition enforced — the same
signed assertion mints unlimited sessions until `NotOnOrAfter`.

- **Detect:** no assertion-ID store (redis/db/set) in the ACS handler; no
  `OneTimeUse` requirement; `allowedClockSkew` so large it doubles the window.
- **Prove:** capture one's own SAML response, POST it twice to the local ACS — second
  login succeeds = replay. (This is *your* assertion on *your* SP — in bounds.)

## 4. XXE through the assertion parser — CWE-611

SAML **is** XML: every attack in 03a's XXE section applies to the SP's assertion
parser and to uploaded IdP metadata.

- **Detect:** parser configured with external entities enabled (`resolve_entities`
  true, default libxml settings, no `defusedxml`), metadata upload endpoints.
- **Prove:** harmless marker entity (`<!ENTITY xxe SYSTEM "file:///etc/hostname">`)
  echoed in an error or attribute — file-read primitive, chain to [03c](03c-ssrf-access-file.md).

## 5. Audience / Destination / Recipient confusion — CWE-345

An assertion minted for SP-A replayed to SP-B: multi-SP IdPs are the normal case, and
SPs that skip `AudienceRestriction`/`Destination`/`Recipient` checks accept any
sibling SP's tokens. Test-SP → prod-SP is the classic cross-environment variant.

- **Detect:** no `Audience` comparison in validation code; `Recipient` of
  `SubjectConfirmationData` unchecked; dev SP cert/URL present in prod metadata.
- **Prove:** on a local two-SP setup, take SP-A's assertion, POST to SP-B's ACS —
  accepted = cross-SP identity forgery.

## 6. Certificate / trust confusion — CWE-347

Metadata carries multiple `<ds:X509Certificate>` entries and the SP treats "any cert
in the blob" as trusted; or the pinning line is commented out during an IdP migration
and never restored; or self-signed IdP certs are accepted unconditionally.

- **Detect:** cert list iterated with "any-of" semantics, `validate_cert=False`,
  pinned-cert code present but commented, `verify=False`-equivalents in the SAML client.
- **Prove:** sign a forged assertion with *your own* key — accepted = trust model is
  decorative (same end-state as §1, different root cause: fix the cert store, not the
  signature check).

## 7. Clock-window abuse — CWE-287

`NotBefore`/`NotOnOrAfter` unenforced or an absurd `allowedClockSkew` (hours/days)
turns every captured assertion into a long-lived credential.

- **Detect:** skew config ≥ 1h, conditions skipped in the validator, replay window
  = assertion lifetime × skew.
- **Prove:** replay an *expired* own assertion on the local SP — accepted = time is
  decorative. Report the effective window in the finding (e.g. "10h replay window").

## 8. NameID / attribute mapping abuse — CWE-287 → privilege escalation

The SP maps `Role`/`Groups`/`Admin` attributes straight into authorization without
pinning *which* attributes the trusted IdP asserts — attacker-supplied attributes in
a (forged or wrapping-broken) assertion become roles.

- **Detect:** attribute → role mapping reading any attribute the assertion carries,
  no allowlist of trusted attribute names, `FriendlyName` used without namespace check.
- **Prove:** marker assertion carrying `Role=admin` → admin session on the local SP.
  Chain tag: `privilege-escalation`.

## Probe discipline

- Passive config/code review first — most SAML findings are visible in one file.
- Forged assertions carry marker identities only (`mr-robot-poc@local.test`) and
  marker attributes; never a real user's NameID, never state-changing actions after
  the forged login — the accepted session *is* the proof.
- Local test IdP/SP only, user-confirmed, bounded requests; clean up test sessions.

## Chaining ideas (Phase 4/5)

- XXE in the parser (§4) → internal file read → secrets → [03c](03c-ssrf-access-file.md) → cloud creds.
- Unsigned/wrapped assertion (§1/§2) → arbitrary account takeover → then normal
  [03b](03b-auth-gateway.md) post-auth testing as the victim role.
- Attribute injection (§8) → admin role → business-logic lanes in [03e](03e-business-logic.md).
- Replay window (§3/§7) + [03l](03l-traffic-interception.md) capture → long-lived
  session theft from any observed SAML hop (report the window; do not harvest real
  assertions).
