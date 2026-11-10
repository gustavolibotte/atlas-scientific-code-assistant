# OIDC identity foundation: security boundary and threat model

## Implemented in Phase 1A.1

- Cryptographically random, per-attempt `state`, `nonce`, browser binding and PKCE verifier.
- RFC 7636 `S256` challenge, with no plaintext PKCE method and no verifier in the authorization URL.
- Strict validation of non-secret OIDC endpoints and explicit redirect URI patterns.
- Single-use callback correlation: both the returning `state` and the initiating browser binding must match.
- Expiring and bounded in-memory pending authorization attempts, synchronized for concurrent access.
- Issuer response parameter comparison when supplied, and safe handling of provider-declined authorizations.
- Data types whose `repr()` does not reveal authorization codes, state, nonce, verifier or browser binding.
- An informational API status route that **never** claims CERN SSO is operational.

## Not implemented; do not assume these protections exist

- Real CERN SSO or CERN client registration.
- HTTP login and callback endpoints; server-side browser-session binding and CSRF-resistant cookies.
- OIDC discovery validation, metadata refresh, JWKS retrieval, signature and signing-algorithm validation.
- Authorization-code exchange, ID-token verification (`iss`, `aud`, `exp`, `iat`, `nonce`, `azp` when applicable), refresh tokens, logout, or session revocation.
- Persistent, distributed session and transaction stores. The provided memory store is **not** production-ready.
- User roles, group membership, delegated access to GitLab CERN, chATLAS authorization or secret storage.

## Threats and controls

| Threat | Phase 1A.1 response | Still required |
| --- | --- | --- |
| CSRF / login-session confusion | Unique state and opaque binding in memory | Bind the browser secret to the initiating secure server-side session |
| Code interception and injection | PKCE S256 material, unique nonce | Complete a real code exchange and validate signed ID token, nonce, and issuer |
| Replay | Atomic single-use consume | Distributed store when deployed with multiple workers |
| Long-lived pending login | Strict short TTL | Session lifetime and revocation policy |
| Abusive request flood | Store capacity bound | Rate limiting, telemetry and horizontal scaling |
| Insecure redirect | Reject non-loopback HTTP, credentials, fragments and query strings | Exact registered callbacks, proxy trust and HTTPS deployment |
| Token/secret leakage | Redacted dataclass representations, no credential API | No secrets in logs, traces, telemetry, frontend or user-submitted reports |
| Malicious OIDC metadata | No HTTP or discovery performed in this phase | Verified metadata and issuer binding, SSRF protection, TLS trust |

## Engineering invariants

1. No API route in Phase 1A.1 returns a login URL, state, nonce, verifier, browser binding, token, or authenticated identity.
2. `AuthorizationCodeGrant` is explicitly **unverified**: it must never confer an authenticated session by itself.
3. The code must never ask for CERN passwords, cookies, personal access tokens, or refresh tokens in an issue, pull request, terminal log or chat.
4. Only official CERN OIDC client registration and the service's documented authorization policies may be used in Phase 1A.2.
5. Preserve independent authorization to chATLAS and GitLab CERN; SSO authentication alone is insufficient.

## Validation

Run `uv run pytest -q tests/unit/test_identity.py tests/security/test_oidc_flow.py tests/contract/test_identity_api.py`, then `uv run python scripts/run_checks.py`. Review the diagnostics before opening a pull request. The real SSO integration must subsequently pass dedicated end-to-end security tests under an authorized CERN client.
