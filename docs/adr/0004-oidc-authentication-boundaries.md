# ADR 0004: Separate OIDC authorization preparation from authentication

- **Status:** Accepted for Phase 1A.1
- **Date:** 2026-11-10
- **Scope:** Identity domain, application contracts and authorization-attempt storage

## Context

ASCA is intended to support CERN SSO through OpenID Connect. It will operate as a local application and, later, as a hosted service. CERN account sign-in must be distinct from authorization to use chATLAS, GitLab CERN or other resources.

An authorization callback containing a code does **not** establish identity. Identity requires exchanging the authorization code using the correct PKCE verifier and validating the resulting signed ID token, issuer, audience, time constraints and nonce. Production login also requires browser-session binding, secure session cookies, deployment-specific redirect URIs and operational controls.

## Decision

1. Use Authorization Code + PKCE S256, unique cryptographic `state`, unique `nonce` and a short-lived authorization attempt.
2. Require a separate opaque browser-binding secret for the attempt. This is an internal contract only; future HTTP handling must bind it to a server-controlled browser session, not a callback query parameter.
3. Treat returned authorization codes as unverified material, never as an authenticated user or a session.
4. Model token verification through an application port, but do not provide an implementation in Phase 1A.1.
5. Keep the initial thread-safe in-memory store bounded and single-use; it is exclusively for offline tests and a local single-process prototype.
6. Allow HTTPS configured endpoints and HTTPS redirects; allow HTTP redirects only to explicit loopback hosts with ports.
7. Expose a read-only API status endpoint indicating that CERN authentication is **not configured**. Do not expose login or token endpoints yet.
8. Keep `cern_sso` advertised as `not_implemented` until a real end-to-end SSO integration has been validated.

## Alternatives considered

- **Automate the CERN web login or reuse browser cookies:** rejected; unsafe and outside the intended authorization flow.
- **Accept callback state alone without session binding:** rejected; permits a cross-session callback mix-up.
- **Implement token exchange and JWT verification using fabricated CERN endpoints:** rejected; discovery, client registration and official provider metadata are prerequisites.
- **Introduce Redis, session tables and public login endpoints immediately:** deferred until authentication architecture and deployment choices are validated.

## Consequences

The Phase 1A.1 module is useful for deterministic tests and architecture boundaries but intentionally cannot log a user in. This prevents a local mock from being mistaken for CERN authentication. No new third-party runtime dependencies, client secrets, network calls or database migrations are introduced.

## References

- RFC 7636, Proof Key for Code Exchange: https://www.rfc-editor.org/rfc/rfc7636
- RFC 9700, Best Current Practice for OAuth 2.0 Security: https://www.rfc-editor.org/rfc/rfc9700
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- CERN Authentication Service documentation: https://auth.docs.cern.ch/
