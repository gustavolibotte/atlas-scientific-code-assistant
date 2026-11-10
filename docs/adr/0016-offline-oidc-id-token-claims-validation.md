# ADR 0016: Validate OIDC ID-token claims without granting identity

- **Status:** Proposed for Phase 1A.2.4E review
- **Date:** 2026-11-10
- **Scope:** Strict offline validation of ID-token claims against explicitly supplied flow context

## Context

PR #13 added verification of compact JWS signatures using public JWK declarations with **unverified CERN provenance**. Its `SignatureCheckedUntrustedOidcPayload` is intentionally forgeable and does not interpret claims. The application's authorization flow separately creates and stores a fresh `nonce`; the corresponding `AuthorizationCodeGrant` carries it onward. No production login flow currently binds JWS signature verification to a trusted key retrieval and consumed authorization attempt.

OIDC Core 1.0 Section 3.1.3.7 requires exact issuer and audience matching, expiration checking, signing-key checks and nonce matching when sent. Additional audiences must be explicitly trusted. RFC 7519 defines `exp`, `iat`, `nbf` as NumericDate values. This phase introduces a deliberately conservative policy compatible with ASCA's native Authorization Code + PKCE flow; it does not assert live CERN compatibility.

## Decision

1. Introduce `validate_untrusted_oidc_id_token_claims` as a pure, offline application function and immutable `ClaimsCheckedUntrustedOidcPayload` domain result. The result is **not** `VerifiedIdentity`, an authenticated session, a trusted CERN principal or a permission grant.
2. Accept only `SignatureCheckedUntrustedOidcPayload`, then independently require approved algorithm (`RS256`, `PS256`, `ES256`) and safe key ID. The input contract is still an ordinary Python dataclass and **can be forged**.
3. Require up to 16,384 bytes of strict UTF-8 JSON object data; reject duplicate JSON members at any nesting depth, invalid numeric constants, malformed input and non-object payloads. Ignore unknown noncritical claims without using them for identity, groups, roles or permissions.
4. Require exact `iss=https://auth.cern.ch/auth/realms/cern`, a nonempty ASCII `sub` (up to 255 characters), a `nonce` matching the trusted pending authorization attempt in constant time, and an expected client ID satisfying ASCA registration syntax. Missing nonce is rejected for ASCA's nonce-bearing code flow.
5. Require `aud` to contain the expected client ID, reject duplicate and unexpected audiences, and permit extra audiences **only** if separately configured in `trusted_additional_audiences`. Multi-audience tokens must contain `azp` equal to the expected client; if `azp` appears in a single-audience token, it must also match.
6. Require integer Unix-second `exp` and `iat` timestamps (no strings, booleans, floating-point or fractional NumericDates), and optionally validate integer `nbf` and `auth_time`. Require a positive bounded lifetime, no future issuance beyond clock skew, no not-yet-valid token and no expired token outside clock skew. Policy defaults: 60-second skew (allowed 0–120), maximum token lifetime 3,600 seconds (configurable 1–86,400). The caller supplies `now` from a trusted clock.
7. Explicitly reject `at_hash`, `c_hash`, and `s_hash` until there is a separate reviewed token/code-binding policy rather than accepting unverified hash values. This conservative choice may require revision after CERN provider compatibility testing.
8. Hide every returned claim from `repr` and sanitize all errors; never log raw payloads, subjects, nonces or other claim content. No HTTP, JWKS fetches, JWS signing, JWT verification routes, credential stores, principals, sessions, or external dependencies are added.
9. Test positive and adversarial cases entirely offline. Include an integration test that generates ephemeral RSA/P-256 keys, produces genuine RS256/PS256/ES256 signatures, passes the result through the existing JWS verifier and validates matching claims without elevating privileges.

## Deliberate limitations and follow-up

- A manually constructed `SignatureCheckedUntrustedOidcPayload` and/or the result dataclass is **not evidence of genuine CERN identity**. Future orchestration must bind the *actual pinned TLS JWKS response* to parsing, key selection, signature and claim checks. No forged dataclass may bypass that boundary.
- `expected_client_id` must come from independently confirmed official registration, and `expected_nonce` from a server-side pending authorization attempt consumed in a replay-resistant manner. This function cannot prove those inputs are trustworthy or that a callback was used only once.
- The 60-second clock-skew default is a policy choice, not a guarantee of provider clock behavior. String/float NumericDates and certain legal optional OIDC claim variations are intentionally unsupported; provider compatibility must be assessed before production.
- The optional `auth_time` field is checked for valid type and future time but no `max_age` or `acr` policy is implemented. Do not claim authentication freshness beyond the checks performed.
- Unknown claims including `email`, `groups`, `roles`, `acr`, `amr` and `email_verified` are not promoted to authority. Resource authorization remains separate.
- Session lifetime, signing-key cache/rotation, ATLAS membership and access to CERN resources remain out of scope; `cern_sso` remains `not_implemented`.

## References

- OpenID Connect Core 1.0, Section 3.1.3.7: https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
- RFC 7519 (JWT), Section 4.1: https://www.rfc-editor.org/rfc/rfc7519#section-4.1
- RFC 8725 (JWT Best Current Practices): https://www.rfc-editor.org/rfc/rfc8725
- ADR 0015: `0015-offline-oidc-jws-signature-verification.md`
