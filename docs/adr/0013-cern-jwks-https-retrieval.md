# ADR 0013: Retrieve CERN JWKS through one constrained HTTPS transport

- **Status:** Proposed for Phase 1A.2.4B review
- **Date:** 2026-11-10
- **Scope:** Bounded public JWKS retrieval, no JWT validation or authentication

## Context

ADR 0012 established strict offline parsing and selection of CERN public JWK declarations. It explicitly does not authenticate the provenance of those bytes. A future cryptographic ID-token verifier must receive keys from an independently pinned HTTPS trust boundary, never from a URL or embedded key supplied by an untrusted JWT.

CERN's reviewed OIDC issuer is `https://auth.cern.ch/auth/realms/cern`, and the reviewed JWKS URL is `https://auth.cern.ch/auth/realms/cern/protocol/openid-connect/certs`. Provider metadata declarations alone are not proof of their own authenticity.

## Decision

1. Add the unmounted infrastructure class `HttpsCernOidcJwksFetcher` and a separate `FetchedUnverifiedOidcJwks` data shape. Neither is invoked by FastAPI routes, startup hooks or the frontend. No login or token-verification capability is enabled.
2. Require an `OidcProviderMetadata` object whose issuer, JWKS URI and advertised ID-token signing algorithms satisfy the fixed CERN policy. Never construct a request destination from caller-controlled URL text or a JWT `jku`, `x5u` or embedded JWK.
3. Issue one `GET` to the **hardcoded** JWKS URL, using a standard-library HTTPS handler with the default verified CA/hostname policy, `ProxyHandler({})` and a redirect-rejecting handler. No cookies, bearer tokens, client credentials or authorization codes are attached.
4. Apply a bounded socket-operation timeout (default 5 seconds, configurable from 0.1 to 15 seconds), read at most 262,145 bytes and reject any response larger than 262,144 bytes. Do not use transparent response decompression. The socket timeout is **not a guaranteed end-to-end elapsed-time deadline**.
5. Require status 200 and exactly one `Content-Type` of `application/json` or `application/jwk-set+json`, optionally with the exact `charset=utf-8` parameter. Reject duplicate or malformed security-relevant headers and compressed bodies. Accept absent `Content-Length`, or a positive bounded length exactly matching bytes received. Allow `Transfer-Encoding: chunked` only without `Content-Length` (the Python HTTP layer decodes chunk framing).
6. Return opaque, bounded bytes with a literal source URL; defer strict JSON parsing to `parse_cern_public_jwks`. No public-key construction, signature verification, JWT claims validation, token storage, permissions or sessions occur here.
7. Convert expected HTTPS, timeout and malformed-response failures into sanitized errors without echoing response bodies, host errors or credentials. Tests use injected fake openers; **tests never perform a real CERN network request**.

## Threat model and limitations

- The pinned URL, TLS verification, blocked redirects and absence of ambient proxies establish the intended retrieval transport when the **default** opener is used in an approved deployment. An injected opener can fabricate bytes and is restricted to offline tests; a manually constructed `FetchedUnverifiedOidcJwks` object does not prove origin.
- Public JWKS data does not require credentials. Actual live CERN retrieval is deliberately deferred to a separately approved integration exercise. The adapter is executable if explicitly called by code, but no application workflow calls it yet.
- The HTTPS client may use system-trusted certificate authorities; it does not provide certificate pinning, independent PKI attestations, an absolute wall-clock deadline, rate limiting, persistent key caching, or a key-rotation/retry policy. These require deployment and security decisions before enabling authentication.
- The response-body cap applies to the HTTP client-visible body. No compressed content is requested or accepted. The HTTP library handles chunked transfer framing.
- The returned bytes must pass the separate ADR 0012 JWKS parser before becoming candidate public keys. Structural key validity is still not cryptographic proof. A dedicated crypto adapter must construct real RSA/P-256 public keys and verify RS256/PS256/ES256 signatures, JOSE headers, and ID-token claims with an authenticated authorization-flow context.
- No CERN API access or ATLAS authorization is implied by this public-data retrieval.

## References

- Existing trusted-issuer discovery policy: `src/asca/application/oidc_discovery.py`
- ADR 0012: `0012-oidc-jwks-public-key-trust-boundary.md`
- RFC 7517 (JWK and JWKS): https://www.rfc-editor.org/rfc/rfc7517
- RFC 8725 (JWT Best Current Practices): https://www.rfc-editor.org/rfc/rfc8725
- OpenID Connect Discovery: https://openid.net/specs/openid-connect-discovery-1_0.html
