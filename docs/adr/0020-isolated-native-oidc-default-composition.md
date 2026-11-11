# ADR 0020: Construct isolated CERN native pre-authentication from default adapters

- **Status:** Proposed for Phase 1A.2.4I review
- **Date:** 2026-11-11
- **Scope:** Explicit, unmounted native-loopback composition without externally injected transport, verifier or metadata

## Context

The native Authorization Code + PKCE chain from ADR 0019 consumes one locally bound authorization attempt, performs a constrained token HTTPS POST and verifies the returned ID token. However, its lower-level constructor deliberately accepts test transports and verifiers. A caller may also supply a forged provider metadata container. These seams are suitable for deterministic unit tests but must not be treated as independent evidence of CERN key provenance or an authenticated identity.

The current ASCA FastAPI application exposes CERN SSO as `not_implemented`, and the existing native code exchange returns forgeable `ExchangedUntrustedCernOidcToken` objects. No approved native loopback listener, official client-registration attestation, durable attempt store or trusted identity composition is available.

## Decision

1. Add `CernOidcNativeUntrustedBootstrap` under infrastructure, and an explicitly non-authenticating status/error contract under domain. Do not change or mount any existing ASCA route or use a `VerifiedIdentity` return type.
2. Accept exactly one operator-declared `OidcClientRegistration` in `NATIVE_LOOPBACK` mode. Reconstruct its validated fields and retain a snapshot so post-initialization mutation is rejected both before and after public discovery.
3. `build()` accepts **no** prevalidated metadata, token, JWS/JWKS, verifier, transport, clock, policy or caller-selected destination. Use `OidcDiscoveryPolicy()` with its fixed CERN issuer and public discovery URL.
4. Build an explicit discovery opener with a system-CA-verified TLS context, no environment proxies and no redirects. Reuse `HttpsOidcMetadataFetcher` for timeouts, response bounds, content-type and strict JSON validation; reuse `OidcDiscoveryService` for discovery policy checks.
5. Recheck the **exact** CERN authorization, token and JWKS endpoints, authorization-code/S256 capabilities and approved asymmetric ID-token algorithms; do not accept a same-origin but different token destination.
6. Construct the existing native exchange using its default HTTPS token transport and default JWKS/JWS/claims verification pipeline. Check the expected concrete adapter types to catch accidental replacement at this composition boundary. These structural checks are **not** TLS attestations and do not protect against deliberate Python monkeypatching or runtime object mutation.
7. Return only `CernOidcNativeCodeExchange`, which remains non-authenticating and unmounted. The `NativeOidcIsolationStatus` contract permanently declares `login=not_implemented`, absent client-registration attestation and absent secured listener. Its values are descriptive and forgeable, not a security capability.
8. Add offline positive and adversarial tests for endpoint injection, metadata forgery, cross-mode confusion, post-construction mutation, fake adapters, proxy environment isolation, error sanitization and the preserved PKCE start.

## Explicit non-goals and unresolved requirements

- **Official client registration:** CERN Application Portal has not been queried for an authorized registration or exact redirect URI; local validation is not attestation.
- **Native listener:** There is no OS-protected loopback listener or callback-acceptance policy. The native binding must remain outside the API until separately reviewed.
- **Authenticated identity:** Neither a token exchange nor validated claims creates a principal here. Existing dataclasses and Python objects remain forgeable.
- **Test seam isolation:** The new constructor has no test injection arguments, but the existing lower-level classes still expose those interfaces. Python monkeypatching, code execution inside the process and direct construction cannot be prevented by type comparisons.
- **Multiworker replay and sessions:** The in-memory attempt store is process-local. No server-side session, permission, group, ATLAS membership, or token persistence is introduced.
- **BFF:** The BFF confidential-client token exchange remains out of scope; native public-client methods cannot be reused for it.
- **Provider availability:** The bootstrap will contact only public CERN discovery when explicitly invoked; it has no caching, retries or absolute request deadline. All tests intercept the fetch and make zero real network calls.

## References

- ADR 0017: `0017-isolated-cern-oidc-verification-orchestration.md`
- ADR 0018: `0018-replay-safe-cern-oidc-web-bff-binding.md`
- ADR 0019: `0019-native-oidc-code-to-token-binding.md`
- RFC 9700 OAuth 2.0 Security Best Current Practice: https://www.rfc-editor.org/rfc/rfc9700
- RFC 8252 OAuth 2.0 for Native Apps: https://www.rfc-editor.org/rfc/rfc8252
