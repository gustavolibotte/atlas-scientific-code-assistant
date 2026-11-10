# ADR 0005: Pin CERN OIDC discovery to an explicit trust anchor

- **Status:** Proposed for Phase 1A.2.1 review
- **Date:** 2026-11-10
- **Scope:** Provider discovery, HTTPS transport, and security boundary

## Context

Phase 1A.1 introduced offline Authorization Code + PKCE S256 preparation. A real CERN login will need official provider metadata, a registered client, authenticated sessions, token exchange and cryptographic ID-token verification. The existence of OIDC endpoints does not provide any of those controls by itself.

Public CERN SSO integrations reference the Keycloak discovery URL:

`https://auth.cern.ch/auth/realms/cern/.well-known/openid-configuration`

The expected issuer is configured independently as:

`https://auth.cern.ch/auth/realms/cern`

The CERN authentication documentation and application portal must remain the authority for actual registration and redirect URIs; a public example is not a registration or a verified live response.

## Decision

1. Keep discovery **opt-in** as a CLI operation. No FastAPI request, application startup or automated test contacts the CERN network.
2. Pin the issuer, discovery URL and endpoint origin in a `OidcDiscoveryPolicy`; never take an issuer or URL from an untrusted request.
3. Require HTTPS with certificate validation, reject redirects, disable cookies and Authorization headers, limit timeouts to 15 seconds and responses to 256 KiB.
4. Reject malformed or duplicate-key JSON, invalid issuer values, remote endpoints outside the expected HTTPS origin, and absent Authorization Code or PKCE S256 support.
5. Select only `RS256`, `PS256` or `ES256` as *eligible future* ID-token algorithms. Reject providers with no intersection. In particular `none` and symmetric HMAC signing are never approved by this component.
6. Expose only a sanitized result. No credentials, client secret, tokens, ID-token contents or raw metadata are printed or stored by the probe.
7. Keep the existing `cern_sso: not_implemented` capability and the `/api/v1/identity/status` response unchanged. Discovery does not authenticate users.
8. Keep unit, security and contract tests deterministic with fixtures and fake network adapters. A live probe may be run manually, but its availability is not a CI dependency.

## Tradeoffs

The policy is intentionally stricter than a generic OIDC client: it currently requires CERN endpoints to share the issuer's origin and explicitly advertise S256. If a legitimate provider responds differently, fail closed and record the evidence before changing the trust model. Do not silently allow HTTP, alternate hosts, downgraded PKCE or unsigned identity tokens.

## Next phase

Phase 1A.2.2 will require a CERN-registered OIDC client, exact authorized callback URIs, server-managed sessions and a audited token verifier. Do not implement token exchange or browser login until the public metadata and client registration are reviewed.

## References

- CERN Application Portal: https://application-portal.web.cern.ch/
- CERN SSO documentation: https://auth.docs.cern.ch/applications/application-configuration/
- CERN OIDC configuration (public reference): https://docs.allauth.org/en/dev/socialaccount/providers/cern.html
- OpenID Connect Discovery 1.0: https://openid.net/specs/openid-connect-discovery-1_0.html
- RFC 9700 (OAuth 2.0 Security Best Current Practice): https://www.rfc-editor.org/rfc/rfc9700
