# ADR 0008: Keep OIDC HTTP callback parsing fail-closed and unmounted

- **Status:** Proposed for Phase 1A.2.2C review
- **Date:** 2026-11-10
- **Scope:** Request origin checks, strict callback parsing, cookie-header selection and unavailable response

## Context

Phase 1A.2.2B created a temporary pre-authentication cookie contract and an application-level correlation service. No HTTP route has been exposed. A future BFF callback will carry an authorization code or an OIDC error, a `state`, possibly `iss`, and a browser cookie. Starlette's convenient request parameter and cookie mappings do not provide enough assurance about duplicate fields or duplicate raw headers for security-sensitive callback processing.

## Decision

1. Add independent FastAPI/Starlette HTTP transport helpers to the API boundary; do not mount any sign-in, callback or token routes.
2. Require the request's ASGI scheme to be `https` and its single raw Host header to match the operator-declared `WEB_BFF` callback authority. Do not trust arbitrary `Forwarded` or `X-Forwarded-*` request headers. A production reverse proxy MUST be independently configured to accept only trusted proxy sources and enforce HTTPS.
3. Require top-level `GET` and an exact raw callback path, with no decoded path aliases.
4. Parse the raw query string with bounded length/field count, strict UTF-8 percent-decoding, unique field names and explicit OIDC field allowlisting. Require exactly one of `code` or `error` and a syntactically valid `state`.
5. Require exactly one raw Cookie header and exactly one well-formed `__Host-asca-oidc-attempt` cookie. Never infer a browser binding from URL parameters or frontend JavaScript.
6. Return an opaque *unverified* callback envelope with sensitive attributes omitted from `repr`. A supplied `iss` parameter must be passed to the application layer for an exact issuer comparison before a code can be accepted (RFC 9207). Correlation with the server-side attempt store, token verification, account authorization and session creation are deliberately separate responsibilities.
7. Provide a generic non-authenticating `503` response that clears the binding cookie and disables caching. Do not echo the authorization code, state, cookie, or provider error.
8. Preserve `/api/v1/identity/login`, `/api/v1/identity/callback` and `/api/v1/identity/token` as nonexistent routes, retain `cern_sso: not_implemented`, and introduce no network calls or new dependencies.

## Important limitations

- This module is **not** enabled authentication. It does not register a CERN client or verify that its callback is actually approved.
- It does not make untrusted proxy headers trustworthy; TLS termination, allowed-host policy and trusted proxy configuration must be enforced before exposure to the Internet.
- If the real CERN provider emits additional authorization response parameters, their use must be reviewed and tested. Unsupported parameters intentionally fail closed.
- Starlette middleware and upstream infrastructure may normalize HTTP headers before ASGI scope creation. Deployment tests must verify raw header handling with the selected reverse proxy.
- Native desktop loopback authentication requires a separate transport policy, not an insecure relaxation of the BFF policy.

## Next step

Before mounting any HTTP sign-in endpoints, add a registered client, audited token endpoint transport, cryptographic ID-token validation, secure session persistence and end-to-end negative tests. Never treat a parsed callback or authorization code as authenticated identity.

## References

- RFC 9700 — OAuth 2.0 Security Best Current Practice: https://www.rfc-editor.org/rfc/rfc9700
- RFC 9207 — Authorization Server Issuer Identification: https://www.rfc-editor.org/rfc/rfc9207
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- ADR 0007: `0007-oidc-web-browser-binding.md`
