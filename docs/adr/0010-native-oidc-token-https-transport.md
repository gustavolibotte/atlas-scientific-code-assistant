# ADR 0010: Contain native-public OIDC token transport behind an unmounted HTTPS adapter

- **Status:** Proposed for Phase 1A.2.3B review
- **Date:** 2026-11-10
- **Scope:** One HTTPS POST for an approved native public-client code-exchange request; opaque response only

## Context

Phase 1A.2.3A introduced `UnsentOidcTokenRequest`, assembled from an unverified authorization-code grant, registered native-loopback callback, PKCE S256 verifier and separately validated CERN OIDC discovery metadata. That object is **not an authentication credential or evidence of login**. A later token exchange must not leak its sensitive form to redirects, an arbitrary destination, logs, HTTP proxies or exception text.

## Decision

1. Introduce `HttpsOidcTokenTransport` as a standalone infrastructure adapter and `UnverifiedOidcTokenHttpResponse` as a domain data shape. Neither is wired into the FastAPI composition root, API routes or the frontend.
2. Pin exactly `https://auth.cern.ch/auth/realms/cern/protocol/openid-connect/token`. A provider endpoint change requires a separate security review, not an automatically followed redirect or arbitrary user-supplied endpoint.
3. Accept only `OidcClientMode.NATIVE_LOOPBACK` and revalidate the complete five-field form, including the exact operator-declared `client_id` and `redirect_uri`, valid PKCE token, nonce and bounded authorization code. Reject any additional, duplicate or malformed fields before opening a connection.
4. For an explicitly invoked exchange, construct one POST with a TLS-verifying standard-library HTTPS handler, a redirect-denying handler and an empty proxy policy. Do not use client authentication secrets, cookies or bearer credentials.
5. Require status 200, exactly one `application/json` Content-Type (optionally `charset=utf-8`), no compression, a sane Content-Length when supplied, and a response body bounded to 65,536 bytes. Invalid HTTP or transport conditions raise sanitized exceptions.
6. Return the raw response bytes as **unverified data** with `repr=False`; do not parse a token, validate any JWT, create an identity or store tokens. A separately reviewed token-response parser and cryptographic verifier are required before any use of the result.
7. All new tests use a fake injected opener. No tests contact CERN, run actual OIDC exchanges or require a registered client.

## Threat model and limitations

- Injection of an opener is exclusively for deterministic tests. The default opener is the intended TLS-verifying, proxy-disabled, redirect-disabled configuration. An arbitrary injected opener is not proof of security.
- No code path in the production application invokes this adapter, but **a developer could explicitly call it**. Do not supply real codes, invoke it against CERN or treat a successful HTTP 200 as authentication until authorized end-to-end integration is reviewed.
- The immutable `UnsentOidcTokenRequest` can be manually constructed; structural checks do not prove its code was issued by CERN. The caller must use the trusted discovery + registration + callback-correlation path. No secret is held in a production session yet.
- Body bytes may contain malicious or malformed JSON: strict parsing, duplicate-member rejection, OAuth error responses, token constraints, signature checks, JWKS validation, issuer/audience/nonce/expiry, replay controls and session lifecycle are **later increments**.
- The fixed token endpoint is intentionally more restrictive than provider metadata to prevent sending an authorization code to a newly declared same-origin path without review. Confirm the registered client and provider behavior before live use.
- Runtime process diagnostics, debugging, network isolation and token zeroization require separate security review. Python's immutable bytes are not memory-zeroized here.
- Native loopback and hosted confidential BFF use distinct OAuth client models; this adapter does not support `WEB_BFF` client authentication.

## References

- RFC 6749: https://www.rfc-editor.org/rfc/rfc6749
- RFC 7636: https://www.rfc-editor.org/rfc/rfc7636
- RFC 8252: https://www.rfc-editor.org/rfc/rfc8252
- RFC 9700: https://www.rfc-editor.org/rfc/rfc9700
- ADR 0009: `0009-native-oidc-token-request-contract.md`
