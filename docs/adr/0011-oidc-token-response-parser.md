# ADR 0011: Parse unverified OIDC token responses without promoting trust

- **Status:** Proposed for Phase 1A.2.3C review
- **Date:** 2026-11-10
- **Scope:** Offline parsing of successful native-public OAuth/OIDC token responses

## Context

PR #8 introduced a pinned, HTTPS-only native OIDC token exchange adapter. Its result is a bounded `UnverifiedOidcTokenHttpResponse` containing opaque response bytes. HTTP 200, valid headers and a successful TLS connection do not establish identity. The application currently has no production sign-in endpoint or verified ID-token workflow.

An OIDC Authorization Code Flow success requires an access token, token type and ID token. OAuth's `expires_in` is recommended, not required. Provider responses can contain harmless extension fields; OAuth and OIDC clients should ignore unrecognized response members. An error response or malformed JSON must not be interpreted as success.

## Decision

1. Add a framework-independent, offline `parse_unverified_oidc_token_response` function and immutable `ParsedUnverifiedOidcTokenResponse` domain contract. **Neither is an authenticated principal.** No HTTP routes or network adapters are added or modified.
2. Require a nonempty, at most 65,536-byte UTF-8 JSON object from an existing unverified HTTP-response object with status 200. Reject duplicate JSON member names at every object nesting depth, malformed UTF-8, nonstandard `NaN`/`Infinity` constants and malformed JSON.
3. Require `access_token`, `id_token` and case-insensitive `Bearer` token type. Enforce bounded printable bearer-token syntax and a three-segment, base64url-shaped compact ID-token representation. This is **syntax only**: no JWT header, payload, signature, claims or keys are verified.
4. Support a positive integer `expires_in` when provided (up to 604,800 seconds); reject booleans, strings, floats, null and unbounded values. Absence is legal and does **not** establish an expiration policy.
5. Allow optional syntactically bounded `refresh_token` and RFC-compliant `scope`. Do not store, refresh, authorize, or grant permissions from these values. A future integration must design a credential lifecycle, storage and scope-validation policy first.
6. Reject top-level OAuth error response fields, unexpected `code` and `state` members in a purported successful token response. Ignore other unrecognized provider extensions rather than promoting them to trusted identity, roles, permissions or session state.
7. Exclude **every** parsed field from `repr`. Raise sanitized errors without including response bodies or credentials. No real CERN credentials or tokens enter tests, logs or diagnostics.
8. Keep BFF confidential-client authentication, ID-token cryptographic validation, JWT/JWKS fetching, claim validation, nonce/audience/issuer comparison, account authorization and authenticated sessions for separate increments.

## Limitations and follow-up requirements

- Only **signed compact JWS-shaped** ID tokens are supported; five-part encrypted JWE requires a separate review. A three-part string is not proof of a valid JOSE algorithm or signature; `alg=none`, HMAC confusion, unverifiable signatures and incorrect claims **must** be rejected by a future cryptographic verifier.
- A syntactically valid access or refresh token is not automatically authorized for any CERN service or resource. Token contents and scopes must not become permissions without provider-side and application-side authorization.
- The optional `expires_in` is untrusted metadata; session lifetimes must not be derived from it before proper validation and policy checks.
- The response bytes and parsed tokens remain present in Python memory. No token persistence, zeroization or lifecycle policy is provided here.
- The HTTP transport and its response-header security policy are separately owned by ADR 0010; this parser receives no response headers and cannot independently verify `Cache-Control` or `Pragma`.
- The 604,800-second upper bound is deliberately conservative and must be reassessed against real provider behavior before integration.

## References

- OpenID Connect Core 1.0, Sections 3.1.3.3 and 3.1.3.5: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 6749, Section 5.1: https://www.rfc-editor.org/rfc/rfc6749#section-5.1
- RFC 6750, Section 2.1: https://www.rfc-editor.org/rfc/rfc6750#section-2.1
- ADR 0010: `0010-native-oidc-token-https-transport.md`
