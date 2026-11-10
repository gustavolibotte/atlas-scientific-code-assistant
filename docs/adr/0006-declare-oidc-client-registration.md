# ADR 0006: Keep CERN client registration declarations separate from authentication

- **Status:** Proposed for Phase 1A.2.2A review
- **Date:** 2026-11-10
- **Scope:** Local client configuration, callback policy and public metadata trust

## Context

Phase 1A.1 introduced offline Authorization Code + PKCE contracts. Phase 1A.2.1 added validated CERN OIDC discovery, but neither increment provides a CERN-registered client, token verification or authenticated sessions. ASCA needs deployment-specific client settings before any login code is exposed. Native loopback callbacks and hosted BFF callbacks have different security requirements.

## Decision

1. Introduce an immutable, **operator-declared** `OidcClientRegistration` containing a client ID, exact callback, deployment mode and minimum OIDC scopes. This is **not** proof that the CERN Application Portal has accepted the registration.
2. Require a loopback IP literal and explicit port for a native HTTP callback. Do not allow `localhost` aliases in this restrictive initial implementation. A deployment-specific exception requires a separate ADR and tests.
3. Require HTTPS and a DNS hostname for a hosted Backend-for-Frontend callback.
4. Reject credentials in callback URLs, query strings, fragments, wildcards, percent-encoding, path traversal, backslashes, control characters and ambiguous callback paths rather than attempting automatic normalization.
5. Allow only `openid`, `profile` and `email` scopes, requiring `openid`. No GitLab or chATLAS delegated permissions are implied or requested.
6. Provide a pure offline configuration bridge to the pre-existing `OidcClientConfiguration`, checking the pinned CERN issuer, origin, Authorization Code, PKCE S256 and approved asymmetric signing algorithms. No login route, network operation, token exchange or session is introduced.
7. Keep `cern_sso: not_implemented` and the public identity status unchanged.
8. Test invalid callbacks, metadata substitution and secret-bearing representations. The existing quality suite remains mandatory.

## Alternatives considered

- **Use the application-provided callback from each browser request:** rejected because it would permit open redirects and callback confusion.
- **Accept any HTTPS redirect:** rejected because registration is deployment-specific and must not be replaced by a user-supplied URL.
- **Reuse a client registration between desktop and hosted deployments:** deferred. Separate registrations and correct client types are preferred when needed.
- **Treat client ID presence as verified registration:** rejected. Only the CERN portal and an authorized live integration can establish acceptance.

## Limitations and next steps

- The operator still must register an ASCA application in the official CERN Application Portal, verify its supported client type, approved scopes and exact callback, and record registration without exporting secrets.
- The bridge is useful only when its metadata input was obtained through the trusted discovery service. An arbitrary Python object with the same shape is not cryptographic evidence.
- Verify whether CERN supports the chosen native loopback callback and port handling before implementing the browser flow. RFC 8252 permits variable loopback ports in the general standard; ASCA currently chooses a fixed configured port until this provider-specific behavior is confirmed.
- Future work must provide server-managed browser binding, secure cookies, an authorized callback route, token exchange, signature and claims validation, session lifecycle and revocation.
- This increment does not grant access to chATLAS MCP or CERN GitLab.

## References

- CERN application registration: https://application-portal.web.cern.ch/
- CERN authentication documentation: https://auth.docs.cern.ch/
- RFC 8252, OAuth 2.0 for Native Apps: https://www.rfc-editor.org/rfc/rfc8252
- RFC 9700, OAuth 2.0 Security Best Current Practice: https://www.rfc-editor.org/rfc/rfc9700
- ADR 0004: `0004-oidc-authentication-boundaries.md`
- ADR 0005: `0005-cern-oidc-discovery-trust-policy.md`
