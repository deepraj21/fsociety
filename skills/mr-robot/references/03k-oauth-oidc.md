# 03k — OAuth 2.0 & OIDC attacks (A01/A07:2025 · WSTG-ATHZ-05 · CWE-601/345/352)

Delegated login is a state machine of redirects, codes, and tokens — each hop a
gateway to bypass. **Active-phase file:** localhost only; you may drive the *local*
flow end-to-end with test accounts at the *local* IdP (Keycloak/Dex/mock-OIDC in
docker-compose counts as local). Never start flows against a real third-party IdP
(Google/Azure) — static analysis only there.

Delegated login via **SAML** is a different protocol with a different failure surface
(signatures, XML wrapping, replay) — that catalog is [03m](03m-saml-federation.md);
load it when the repo speaks SAML assertions.

## Find it (Phase 1/2)

- **Static:** `next-auth`, `passport`, `oauthlib`, `omniauth`, `spring-security-
  oauth`, `openid-connect`, `jose`/`jwt` libs, `/authorize`, `/callback`, `/token`,
  `/.well-known/openid-configuration`, `auth.js`/`Auth0` SDK config.
- **Live:** `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`
  reachable → issuer, endpoints, grant types, `code_challenge_methods_supported`
  (all of it is intel). ffuf paths.txt already covers `/.well-known/*`.

## 1. redirect_uri manipulation — CWE-601 → token/code theft

The single highest-value OAuth bug: if the AS accepts a URI it was not registered
for, the auth **code lands on the attacker's server**.

- **Probes (bounded, in order — stop at first acceptance):**
  ```
  # exact-match bypass attempts against the LOCAL authorize endpoint:
  /authorize?...&redirect_uri=https://app.localhost.evil.com/callback     # suffix trick
  /authorize?...&redirect_uri=https://app.localhost/callback/../../evil    # path traversal
  /authorize?...&redirect_uri=https://app.localhost/callback%40evil.com    # @/encoding
  /authorize?...&redirect_uri=http://app.localhost:9999/callback           # scheme/port drift
  /authorize?...&redirect_uri=//evil.com/callback                          # protocol-relative
  ```
- **Prove:** the authorize endpoint *redirects to the manipulated URI* (302 with
  `?code=` on a host you did not register) = confirmed **high** (chains: code →
  token at `/token` → account takeover → `tags: account-takeover`).
- **Verify in source:** registered-URI matching must be exact string equality
  (prefix/`startsWith`/regex-without-anchors/`endsWith` = vulnerable patterns;
  grep the AS/client config).
- **Open-redirect chaining (03c):** a redirect_uri allowlist containing a domain
  with an open redirect (`https://app.localhost/out?u=`) → allowlisted redirector
  forwards code to attacker. Test the *combination*, not just each piece.

## 2. state & CSRF on the callback — CWE-352

- **Prove:** complete a login, capture the authorize URL; re-send the callback
  (`/callback?code=…`) *without* state, or with attacker-set state, or replay an old
  code — accepted = login CSRF / code replay (medium-high; account linking: attacker
  binds victim's session to attacker's IdP account → victim acts as attacker, or the
  reverse).
- **Verify:** state generated per-request, single-use, compared on callback; nonce
  bound for OIDC; codes single-use at the AS (replay second POST to `/token` →
  must fail).

## 3. PKCE (RFC 7636) — CWE-345

- **Downgrade:** public client sends a request *without* `code_challenge` — if the
  AS still issues a code (no `code_challenge` required for that client), PKCE is
  optional = stolen-code replay works (high for public/SPA/mobile clients).
- **Weak challenge:** `code_challenge_method=S256` must be used; `plain` accepted?
  Static finding (medium).
- **Bypass:** send a challenge, then POST `/token` with a *different* verifier —
  AS must reject; accept = PKCE not enforced (high).
- **Verify in source:** verifier length ≥43, single-use, method pinned to S256.

## 4. Token validation at the client — CWE-345 (confused deputy)

Every check the AS does is *not* repeated by your app — verify the app does them:

- **`aud`:** token minted for *another* app accepted? Prove locally with a second
  registered client — request its token, replay against the app → accepted = **high**
  (token confusion across first-party apps).
- **`iss`:** issuer pinned to an allowlist, or compared to a variable from config
  an attacker influences (Host header → issuer discovery rewrite)?
- **`alg`:** `none` accepted; RS256→HS256 confusion (verify with public key as HMAC
  secret — same as 03b JWT lane); keyid→JWKS fetch = SSRF (cross-link 03c).
- **`exp`/`nbf`/`azp`:** clock-skew windows absurdly wide; `azp` (authorized party)
  unchecked on multi-audience tokens.
- **Mix-up attack (RFC 9207):** two IdPs, callback lacks issuer binding — token from
  IdP-B replayed to the app expecting IdP-A. Static: does the callback pin which
  provider the code belongs to? (AS `iss` in response + client-side binding.)

## 5. Implicit & misconfigured grants — A01

- **Implicit flow (`response_type=token`)** still enabled → tokens in URL fragment,
  leaked via Referer/history/XSS (cross-link 03a) — static finding, medium-high.
- **`response_mode=form_post`** accepted from attacker input → HTML POST to
  attacker-controlled body parsing.
- **Grant confusion:** client_credentials/refresh tokens handed to public clients;
  refresh tokens not rotated (reuse-detection missing at AS).
- **Device/code & PKCE-less ROPC** on resource-owner password grant — password
  harvesting path if the app proxies it.

## 6. OIDC app-side specifics

- **ID token vs access token mixup:** app calls `/userinfo` with an ID token, or
  accepts `id_token` where an access token belongs — token-typing confusion.
- **Nonce:** replayed nonce accepted (prove: same authz URL twice → both callbacks OK).
- **Signed-out / logout:** `post_logout_redirect_uri` open-match (phishing);
  RP-initiated logout missing → session survives "logout" at IdP (03b SESS-06 cousin).
- **Account linking (the takeover classic):** app links IdP identity to a local
  account by *verified_email only* — prove with a local IdP test account whose
  email matches an existing local user → linked without proving control of the local
  account (high; `tags: account-takeover`).

## Probe discipline

Local IdP + local app only; ≤10 redirect_uri probes; ≤5 token replays; all test
flows with marker accounts (`mr-robot-poc@localhost`) whose created sessions/links
you remove afterwards (verify removal). Codes/tokens captured are test tokens —
never real user tokens; if a real token ever appears in the flow, stop and report
the exposure without using it.

## Chaining ideas (Phase 4/5)

redirect_uri gap → code theft → takeover (`account-takeover`, NO-GO) ·
state missing → login CSRF → account linking takeover · PKCE downgrade → stolen-code
replay (public clients) · aud confusion → cross-app token reuse · open redirect (03c)
inside allowlisted domain → redirector abuse · account-link-by-email → takeover ·
token in Referer → XSS leakage (03a) · JWKS URL fetch → SSRF (03c).
