# ADR 0014: Construct OIDC asymmetric public keys without promoting trust

- **Status:** Proposed for Phase 1A.2.4C review
- **Date:** 2026-11-10
- **Scope:** Offline construction of RSA and P-256 public key objects; no JWS signature verification

## Context

PR #10 introduced strict, unverified-provenance CERN JWKS parsing and exact `kid`/algorithm selection. PR #11 introduced an isolated, bounded, pinned HTTPS JWKS retrieval adapter. The parsed JWK fields are still ordinary Python values and can be manually forged. This increment must check public-key representation using an established cryptographic backend, while keeping key source provenance, JWS verification, OIDC claims and session creation strictly separate.

## Decision

1. Add an isolated `construct_cern_oidc_public_key(jwks, *, kid, algorithm)` function and an immutable `ConstructedUnverifiedOidcPublicKey` shape. Reuse the exact, pinned `select_cern_public_jwk` policy and independently recheck the selected public fields against manipulated dataclass inputs.
2. Use PyCA `cryptography` as the sole new runtime dependency. For the existing GitHub Actions matrix, constrain it to `cryptography>=46.0.7,<49`: releases 49 and newer no longer distribute macOS x86_64 wheels. The lockfile must be resolved and committed on the contributor's Mac, then verified on Python 3.11–3.13 and Linux/macOS in CI. This compatibility cap is temporary and should be revisited alongside runner architecture updates and security advisories.
3. Accept only a structurally valid RSA key for `RS256` or `PS256`. Recheck 2,048–8,192-bit odd modulus, minimal representation, odd exponent between 3 and 2^32−1, and `e < n`. Construct using `rsa.RSAPublicNumbers(...).public_key()`. Reject conflicting EC fields.
4. Accept only an `ES256` EC key with 32-byte x/y coordinates and `P-256` curve. Construct using `ec.EllipticCurvePublicNumbers(..., ec.SECP256R1()).public_key()` so the cryptography backend rejects invalid/off-curve points. Reject conflicting RSA fields.
5. Return a public-only cryptographic object with `kid`, exact algorithm, and key type. Hide the key instance from `repr`. Sanitize construction errors and never use raw key fields, tokens, or backend errors in user-visible exception strings.
6. Perform no network call, private-key construction, signature verification, JWT processing, authentication, session creation, or authorization. Tests use synthetic public parameters and an established P-256 generator point.
7. Keep the implementation unmounted; do not wire it into the FastAPI application or production identity lifecycle.

## Limitations and security boundaries

- Public-key construction **does not establish JWKS provenance**. A dataclass carrying the expected CERN URL can be forged; the future orchestration must bind pinned HTTPS retrieval to strict parsing, select an approved key and enforce rotation policy before signature verification.
- `RSAPublicNumbers.public_key()` confirms that the public parameters can be represented by the cryptography backend, **not** that an RSA modulus was generated as the product of appropriate secret primes. The tests intentionally use synthetic public RSA integers and do not claim certificate-backed identity.
- P-256 point construction verifies mathematical curve membership but does **not** verify a JWS signature or confirm CERN issued the token.
- No signed JOSE header is parsed here. The later verifier must reject `alg=none`, HMAC algorithm confusion, remote `jku`/`x5u`, embedded `jwk` substitution, unsupported `crit`, and malformed signature encodings, including the fixed-length raw ECDSA signature format.
- Verified signatures still require exact `iss`, `aud`, `azp` when appropriate, `nonce`, `exp`, `iat` and other OIDC claim policy checks before identity or session creation.
- The installed dependency and `uv.lock` must be reviewed as part of this PR. Do not use an unlocked environment to justify merging.

## References

- ADR 0012: `0012-oidc-jwks-public-key-trust-boundary.md`
- ADR 0013: `0013-cern-jwks-https-retrieval.md`
- RFC 7517, JSON Web Key: https://www.rfc-editor.org/rfc/rfc7517
- RFC 7518, JSON Web Algorithms: https://www.rfc-editor.org/rfc/rfc7518
- RFC 8725, JWT best current practices: https://www.rfc-editor.org/rfc/rfc8725
- PyCA `cryptography`: https://cryptography.io/en/latest/
