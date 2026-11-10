# ADR 0007: Isolate OIDC web-browser binding from login and sessions

- **Status:** Proposed for Phase 1A.2.2B review
- **Date:** 2026-11-10
- **Scope:** Offline cookie policy and authorization-attempt correlation for an HTTPS Backend-for-Frontend (BFF)

## Context

Phase 1A.1 introduced PKCE S256, nonce, state and an authorization-attempt store. Phase 1A.2.1 validated public CERN OIDC metadata. Phase 1A.2.2A added the **operator-declared** client registration preflight. None of these increments authenticates a user. The existing authorization service returns an opaque `browser_binding`, but HTTP code must never put it in a URL or expose it to frontend JavaScript.

A web application needs a way to return that binding to the backend on a top-level OIDC callback, while preventing browser mix-ups, callback replay and accidental propagation to less trusted origins. We must keep this mechanism separate from authenticated application sessions and from the native desktop loopback flow.

## Decision

1. Introduce an immutable temporary `OidcBrowserCookie` contract and a small application adapter for **WEB_BFF only**. The native loopback mode does not reuse this cookie policy.
2. Use a host-only `__Host-asca-oidc-attempt` cookie with `Secure`, `HttpOnly`, `Path=/`, `SameSite=Lax`, no `Domain`, and bounded `Max-Age` (30–900 seconds). `Lax` supports a **top-level GET redirect** from CERN; other response modes require a separate decision.
3. Only a cryptographically generated, opaque authorization-attempt binding is placed in the cookie. A valid-looking value is not accepted as authoritative: the existing server-side attempt store must still match the cookie binding and `state`, and consume the attempt once.
4. Reject missing, duplicate, malformed, non-ASCII or oversized cookie headers. Do not log the cookie, binding or generated authorization URL; dataclass representations hide them.
5. Provide a host-bound cookie-clearing header. Future HTTP transport must clear the cookie in a `finally`-equivalent path after **both** successful and unsuccessful callbacks.
6. No login or callback HTTP endpoint is exposed in this increment. The frontend does not receive tokens, nor does the pre-authentication cookie create an authenticated application session.
7. The composition root must create `OidcAuthorizationService` from the *same* validated client registration and trusted discovery metadata. This small adapter does not independently prove CERN registration.
8. Keep CERN SSO capability reported as `not_implemented`. No new runtime packages, network access or changes to existing routes.

## Explicit limitations

- This is an **offline transport contract**, not a complete BFF security design. It lacks actual HTTPS routing, origin enforcement, trusted proxy configuration, token exchange, cryptographic ID-token verification, authenticated session rotation, revocation, rate limiting and distributed storage.
- A cookie carrying an authorization binding is not a login session or an authorization credential. Session fixation defenses must be designed separately for authenticated identities.
- Browser support for `__Host-` cookies, cookies on cross-site redirects, and provider callback behavior must be tested in a real authorized deployment before enabling live login.
- The in-memory attempt store remains single-process and test-only. It must be replaced before multiworker or hosted deployment.
- An attacker-controlled value that matches the cookie's syntax still fails without a matching server-created attempt and `state`.

## References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet)
- [NIST SP 800-63B, Session Management](https://pages.nist.gov/800-63-4/sp800-63b/session/)
- [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- ADR 0004: `0004-oidc-authentication-boundaries.md`
- ADR 0006: `0006-declare-oidc-client-registration.md`
