# ADR 0018: Consume a browser-bound CERN OIDC authorization attempt once

- **Status:** Proposed for Phase 1A.2.4G review
- **Date:** 2026-11-10
- **Scope:** Isolated replay-resistant correlation of web BFF state, nonce, and client configuration; no login

## Context

Previous increments provide an `OidcAuthorizationService`, an atomic `InMemoryAuthorizationAttemptStore`, a strict `__Host-` BFF cookie policy, a constrained CERN client-registration declaration, and a non-authenticating `CernOidcVerificationPipeline`. The pipeline currently receives `expected_client_id` and `expected_nonce` from an arbitrary caller. Although they are validated syntactically and against signed token claims, the pipeline cannot establish that a particular browser initiated and consumed a specific authorization attempt.

The existing `OidcAuthorizationService.finish()` atomically consumes an attempt when the original browser binding and returned `state` match, before it returns `AuthorizationCodeGrant` carrying the stored nonce and PKCE verifier. The store is thread-safe but **process-local**, and the grant is forgeable Python data. No CERN authorization-code exchange is bound to the token response.

## Decision

1. Introduce `CernOidcReplaySafeBffBinding` in infrastructure, with a small, non-authenticating result contract in domain. Keep architecture dependencies directed inward; no API route is mounted.
2. Support only **WEB_BFF** registrations, not native loopback or production multiworker deployment. Reconstruct and validate operator-supplied registration data and require the exact CERN issuer, authorization endpoint, token endpoint, JWKS URI, approved signing algorithms, code flow and S256. These local checks **do not attest registration in the CERN Application Portal**.
3. Construct the `InMemoryAuthorizationAttemptStore` and `OidcAuthorizationService` **internally**, rather than accepting externally constructed grants, attempted nonces or arbitrary stores. Use the existing random browser binding, state, nonce, PKCE verifier, and cookie serialization.
4. Expose `begin()` for an offline, unmounted BFF authorization attempt. The hosting BFF must use HTTPS, set the returned cookie with its `Secure`, `HttpOnly`, host-only `__Host-` policy, not expose the browser binding to JavaScript, and clear that cookie on both successful and unsuccessful callbacks.
5. Expose `check_callback(cookie_header, state, code, tokens, response_issuer)` for offline correlation. Check bounded, visible callback code; parse the cookie through the existing strict parser; require exact state and cookie binding; **atomically consume the attempt before token verification**. Derive `expected_nonce` exclusively from the consumed attempt and `expected_client_id` exclusively from the internally constructed client configuration. No caller-supplied nonce or client ID is accepted by this method.
6. If signature, claims, or other downstream verification fails after consumption, the attempt remains consumed. Invalid cookies and mismatched state do not consume another browser's attempt. Concurrent redemptions can succeed at most once for a shared in-memory store.
7. Use `CernOidcVerificationPipeline` with explicit validated client ID and nonce. Pipeline injection is permitted for **offline tests only** and does not establish TLS provenance; returned objects remain ordinary, forgeable Python data without authentication authority.
8. Keep error messages sanitized and avoid storing access/refresh tokens or raw ID tokens in this binder. Bound input sizes, the attempt TTL (30–900 s), cookie lifetime (30–900 s, no longer than attempt TTL), store capacity and verification clock.
9. Return `BoundUntrustedCernOidcToken` with minimal, repr-hidden claims, never `VerifiedIdentity`, a session, an access token, authorization, CERN or ATLAS membership.

## Critical limitations

- **No code-to-token provenance**: the caller supplies `ParsedUnverifiedOidcTokenResponse` separately. Although the browser attempt is consumed and its nonce must match the signed ID token, this increment does **not** exchange the particular callback code through the CERN token endpoint, bind an HTTP response to that exchange, or provide proof that the supplied token response came from that code. Do not use this class to authenticate anyone.
- **No independent registration attestation**: `OidcClientRegistration` is an operator declaration. Live registration and redirect URI must be confirmed through an authorized CERN administrative workflow.
- **No hosted replay guarantee**: `InMemoryAuthorizationAttemptStore` is process-local. For a hosted BFF, a strongly consistent multiworker store with atomic consume, expiry, rate limiting and operational protections must replace it, with another security review.
- **No session handling**: cookie clearing, route protections, HTTPS termination, CSRF protections, identity construction and server-side sessions remain to be implemented at the BFF boundary.
- **No independently trusted JWKS provenance when injection is enabled**: the pipeline may accept test-injected transports and cannot promote its result to a login capability.
- **No live network tests**. Tests use synthetic callbacks and ephemeral signing keys, including RS256, PS256 and ES256, with in-memory fake HTTP responses.

## References

- ADR 0017: `0017-isolated-cern-oidc-verification-orchestration.md`
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- OAuth 2.0 Security Best Current Practice (RFC 9700): https://www.rfc-editor.org/rfc/rfc9700
- OAuth 2.0 for Browser-Based Apps (RFC 9700 guidance and BFF pattern): https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps
