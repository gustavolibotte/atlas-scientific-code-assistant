# ADR 0009: Prepare an unsent native-public CERN OIDC token request

- **Status:** Proposed for Phase 1A.2.3A review
- **Date:** 2026-11-10
- **Scope:** Offline authorization-code token request, native public OIDC clients only

## Context

Phase 1A.1 created an unverified, browser-correlated `AuthorizationCodeGrant` containing an authorization code, PKCE S256 verifier, nonce and exact redirect URI. Phases 1A.2.1–1A.2.2C introduced pinned CERN discovery, operator-declared client registration, temporary BFF browser cookies and strict, unmounted HTTP callback parsing. No token is exchanged or verified and CERN SSO remains disabled.

A future native client must prepare an OAuth 2.0 Authorization Code token request without allowing arbitrary token endpoints, redirect substitution, code leakage into logs, or unreviewed client authentication behavior. The hosted BFF may require a confidential-client authentication method that must be confirmed in the CERN Application Portal before implementation.

## Decision

1. Introduce a pure, offline `prepare_cern_native_token_request` application function. It **does not send HTTP** or contact CERN.
2. Accept only `OidcClientMode.NATIVE_LOOPBACK`; reject `WEB_BFF` rather than silently omitting required confidential-client authentication.
3. Recheck the existing CERN discovery and registration preflight. The metadata must be obtained separately through trusted discovery; an object of the correct type alone is not provider evidence.
4. Require the grant redirect URI to equal the declared registration URI exactly. Require a syntactically valid PKCE verifier and bounded, printable authorization code; preserve the expected nonce for a future ID-token verifier.
5. Build an `application/x-www-form-urlencoded` POST body with precisely `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id` and `code_verifier`.
6. Exclude the form body and expected nonce from the request object's `repr`. Return sanitized error messages and never write secrets to logs or diagnostics.
7. Expose fixed headers only (`Content-Type`, `Accept`, `Cache-Control`), with no Authorization, cookie or client secret in the request contract.
8. Do not create routes, HTTP adapters, authenticated sessions, ID-token verifiers, login affordances or new dependencies.

## Security limitations

- A well-formed request is **not** proof of a registered CERN client, an authorized code, a valid token, or an authenticated user.
- A future HTTPS adapter must pin the trusted endpoint and enforce no redirects, certificate verification, timeouts, bounded response bodies, restricted content types, secret-safe diagnostics and response validation before any network use.
- Codes and PKCE verifiers must be treated as ephemeral credentials and never enter user-facing traces, repositories or logs.
- Confidential web BFF client authentication requires a separate ADR based on the actual authorized CERN client registration and supported token endpoint authentication methods. No client secret is requested or accepted here.
- Token response parsing, JWT signature verification (using trusted JWKS), issuer, audience, nonce, expiry and replay checks, then authenticated sessions are subsequent separately tested increments.
- The in-memory authorization-attempt store remains unsuitable for multiworker or production deployments.

## References

- RFC 6749: OAuth 2.0 Authorization Framework — https://www.rfc-editor.org/rfc/rfc6749
- RFC 7636: Proof Key for Code Exchange — https://www.rfc-editor.org/rfc/rfc7636
- RFC 8252: OAuth 2.0 for Native Apps — https://www.rfc-editor.org/rfc/rfc8252
- RFC 9700: OAuth 2.0 Security Best Current Practice — https://www.rfc-editor.org/rfc/rfc9700
- ADR 0006: `0006-declare-oidc-client-registration.md`
- ADR 0008: `0008-oidc-http-transport-boundary.md`
