# ADR 0017: Compose CERN OIDC JWKS, JWS and claims checks without enabling login

- **Status:** Proposed for Phase 1A.2.4F review
- **Date:** 2026-11-10
- **Scope:** Ordered, bounded public-key retrieval and offline ID-token validation; no authentication

## Context

ADRs 0012–0016 introduced independent, explicitly non-authenticating components: strict JWKS declaration parsing, pinned HTTPS retrieval, mathematical public-key construction, JWS signature checking and OIDC claims validation. Passing a manually instantiated JWKS or signature-checked Python dataclass between these components does not establish CERN key provenance. No existing application workflow binds their execution in order.

## Decision

1. Add an unmounted infrastructure-level `CernOidcVerificationPipeline`; application and domain layers cannot import infrastructure under the project's architecture guard.
2. The pipeline **does not accept externally parsed JWKS, caller-selected public keys or claimed signature-check results**. It calls an `HttpsCernOidcJwksFetcher`, checks the literal response source, parses the fetched bytes, verifies the supplied token's signature and checks its claims in that sequence. Only the pinned CERN issuer and JWKS URI are permitted. Authentication flow metadata is rechecked against exact, reviewed CERN authorization and token endpoints.
3. Instantiate the standard fetcher internally when no fetcher is supplied. An injectable `HttpsCernOidcJwksFetcher` is accepted solely to permit deterministic offline tests using fake openers. Such a fake does **not** prove TLS provenance. Python monkeypatching and manual dataclass construction remain possible; **no returned object is an authentication capability**.
4. Preflight malformed metadata, missing/malformed token inputs, client IDs, nonces and policy parameters **before** attempting network access. A well-formed but incorrect client ID or nonce must fail at the downstream signed-claims check; it is not inferred from JWT content.
5. Require one successful public JWKS HTTPS retrieval for each invocation. Reuse the reviewed 262,144-byte response cap, strict JSON/JWK-set media types, redirect rejection, proxy isolation, TLS certificate and hostname verification, and request timeout (not an absolute deadline). No retries, dynamic key URLs, network caching or fallback paths are added.
6. Preserve exact `kid` and `alg` selection, RS256/PS256/ES256 verification, strict JSON, issuer, audiences, `azp`, nonce and timestamp checks from prior phases. Never accept roles/groups or optional token hash claims as proof of authorization.
7. Return `CheckedUntrustedCernOidcToken`, with hidden, minimal check details. It is neither the existing `VerifiedIdentity` type nor a user principal, browser session, login result or permission grant. All expected errors are sanitized.
8. Add adversarial and positive tests with ephemeral synthetic RSA and P-256 key pairs; use a real `HttpsCernOidcJwksFetcher` supplied with a fake in-memory HTTP opener. Tests **do not call the live CERN network**.

## Deliberate limitations and next work

- **Client registration and nonce provenance are not established.** The caller supplies `expected_client_id` and `expected_nonce`, which could be forged or replayed. A subsequent stage must obtain these from an independently approved client registration and a single-use, browser-bound server-side authorization attempt.
- **The test-injection boundary is not a provenance attestation.** A fake fetcher returning attacker public keys can pass mathematical verification of an attacker-signed JWT. The pipeline therefore deliberately returns a non-authenticating result. A future production-only composition must prevent test injection from being used as a source of identity authority.
- **No login endpoint is mounted** and `cern_sso` remains `not_implemented`. There is no callback consumption, access/refresh token persistence, session creation, API authorization, group/ATLAS membership proof, or CERN data access.
- **No live provider-compatibility exercise:** supported JWS header forms, optional hash claims, audience policy and signing algorithms need confirmation against permitted CERN test credentials before enabling login.
- **No caching or rotation policy:** each explicit check performs one fetch; use must be rate-limited and designed for JWKS rotations and outages before production.
- **No absolute request deadline**: existing transport's timeout bounds individual socket operations, not total wall-clock time. TLS relies on system-trusted certificate authorities rather than independent certificate pinning.

## References

- `0012-oidc-jwks-public-key-trust-boundary.md`
- `0013-cern-jwks-https-retrieval.md`
- `0014-oidc-cryptographic-public-key-construction.md`
- `0015-offline-oidc-jws-signature-verification.md`
- `0016-offline-oidc-id-token-claims-validation.md`
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- JWT Best Current Practices, RFC 8725: https://www.rfc-editor.org/rfc/rfc8725
