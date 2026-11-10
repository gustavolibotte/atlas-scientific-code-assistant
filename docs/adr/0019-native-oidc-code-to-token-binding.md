# ADR 0019: Bind a consumed native authorization code to its token HTTPS POST

- **Status:** Proposed for Phase 1A.2.4H review
- **Date:** 2026-11-11
- **Scope:** Unmounted native loopback Authorization Code + PKCE composition; no login authority

## Context

PR #16 introduced an isolated, process-local, replay-safe **web BFF** callback binder. That binder deliberately accepts a token response independently of the callback code and cannot prove code-to-token provenance. The existing `prepare_cern_native_token_request` and `HttpsOidcTokenTransport` instead implement a tightly constrained **native public-client** POST; notably, the transport rejects `WEB_BFF` registrations. A production web BFF would additionally require an approved confidential-client authentication mechanism, which is not present. Reusing the native transport as a BFF exchange would silently cross this boundary.

## Decision

1. Introduce `CernOidcNativeCodeExchange` in infrastructure and `ExchangedUntrustedCernOidcToken` in domain. This is a **separate native-only increment**, not a replacement for the web BFF binder.
2. Reconstruct and validate the caller's `OidcClientRegistration` in `NATIVE_LOOPBACK` mode and require the exact reviewed CERN issuer, authorization, token and JWKS endpoints, code flow, S256 and approved signing algorithms. This is local validation, **not proof of accepted CERN registration**.
3. Construct a private `OidcAuthorizationService` and `InMemoryAuthorizationAttemptStore`; `begin()` creates state, a browser/native-host binding, nonce and PKCE S256 verifier. No session, browser cookie or token is issued.
4. Expose `exchange_callback` with only the native binding, `state`, callback `code` and optional callback issuer. It does **not** accept a pre-supplied token response, JWS, nonce, code verifier, parsed JWKS or principal.
5. Atomically consume the attempt once. From the consumed `AuthorizationCodeGrant`, use the existing approved native request builder to construct exactly one POST with the original code, redirect URI, client ID and PKCE verifier. Assert that the prepared nonce equals the consumed attempt's nonce.
6. Use `HttpsOidcTokenTransport` for the fixed CERN token endpoint with TLS validation, no redirects, environment-proxy isolation and request/response size limits. Parse the returned token response using `parse_unverified_oidc_token_response`, then invoke the existing JWKS/JWS/claims verification pipeline with the internally derived client ID and nonce.
7. On any failure after consumption, **do not restore** the attempt. A concurrent or later replay cannot produce a second POST within the same process. Sanitize all expected errors; never log token response, authorization code, PKCE verifier or nonce.
8. Return an immutable minimal `ExchangedUntrustedCernOidcToken` with repr-hidden fields. It is deliberately **not** `VerifiedIdentity`, a session, an access-token holder or an authorization capability. It remains forgeable Python data.
9. Permit injected HTTP transports and verification pipelines **only for offline tests**; their output cannot attest CERN key provenance. Tests use synthetic credentials, ephemeral RSA/P-256 keys, fake in-memory HTTP responses and no CERN network access.

## Security boundaries and limitations

- **No WEB_BFF support:** The existing HTTPS token transport explicitly supports native public clients only. This increment does not add confidential-client secrets, client assertion support, a BFF token POST, session cookies or browser login routes. The previously added BFF binder remains non-authenticating.
- **No independently confirmed registration:** The official CERN Application Portal client ID, redirect URI and client mode must be confirmed through an authorized administrative process before production.
- **Native callback binding is the host's responsibility:** The native loopback listener must protect the local binding from unauthorized processes, validate the response and safely handle URL/callback routing. This offline class does not install a listener or supply operating-system-level protections.
- **In-memory only:** The single-use store is atomic only within one process, not across application workers or machines.
- **No trusted authentication capability:** Fake transports/verifiers can be injected and all result dataclasses remain forgeable. A later separately reviewed production-only composition must prevent testing seams from granting identity.
- **No rate limiting, retries, outage policy or key cache:** Every explicit verification calls the existing JWKS fetcher once; production rotation, caching and availability policies remain unresolved.
- **No live provider compatibility validation:** CERN's actual token endpoint responses, optional hash claims, supported signing algorithms and registered client authentication requirements must be checked before enabling login.
- **No persistence:** Access/refresh tokens, sessions, subject roles or ATLAS/CERN membership are not retained or asserted. `cern_sso` remains `not_implemented`.

## References

- ADR 0017: `0017-isolated-cern-oidc-verification-orchestration.md`
- ADR 0018: `0018-replay-safe-cern-oidc-web-bff-binding.md`
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- OAuth 2.0 PKCE, RFC 7636: https://www.rfc-editor.org/rfc/rfc7636
- OAuth 2.0 Security Best Current Practice, RFC 9700: https://www.rfc-editor.org/rfc/rfc9700
