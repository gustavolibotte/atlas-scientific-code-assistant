# ADR 0012: Parse CERN JWKS public signing-key declarations before cryptographic verification

- **Status:** Proposed for Phase 1A.2.4A review
- **Date:** 2026-11-10
- **Scope:** Strict, offline JWKS parsing and exact public-key selection; **no signature verification**

## Context

PR #9 introduced an unverified OAuth/OIDC token-response parser. Its signed-JWS-shaped `id_token` is still an untrusted string. Verifying a future JWT will require vetted asymmetric public keys from the **pinned CERN issuer**, rather than keys, algorithms, `jku` links, `jwk` values or X.509 URLs offered by the token itself.

The existing discovery policy pins `https://auth.cern.ch/auth/realms/cern`; this increment uses `https://auth.cern.ch/auth/realms/cern/protocol/openid-connect/certs` as an exact **declared** JWKS endpoint. Neither a Python metadata object nor a valid JSON document proves that the document was actually obtained from CERN.

## Decision

1. Introduce a pure `parse_cern_public_jwks(raw_json, metadata)` function, a pure `select_cern_public_jwk(jwks, kid=..., algorithm=...)` function, and immutable public-key contracts. Nothing performs network requests, authenticates a user, verifies a JWT, or creates a session.
2. Require CERN's exact pinned issuer and JWKS URI plus a nonempty subset of the provider-advertised and locally approved `RS256`, `PS256`, `ES256` algorithms. The caller MUST independently obtain provider metadata through trusted discovery and JWKS bytes from a future TLS-verified, pinned fetcher.
3. Bound JWKS documents to 262,144 bytes and 64 declared keys. Require strict UTF-8, an object with a `keys` array, distinct JSON member names at all depths, and unambiguous unique `kid` values. Ignore unrecognized noncritical JSON extensions without granting authority.
4. Reject private or symmetric material (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) and remote key references (`x5u`, `jku`, `jwk`). Do not trust optional `x5c` or thumbprints as a replacement for locally validated key parameters; they are ignored.
5. Accept only signing-use declarations (`use=sig`) with optional `key_ops=[verify]`. Skip explicitly non-signing or unapproved-algorithm entries. Require at least one structurally acceptable asymmetric public signing key.
6. For `RS256`/`PS256`, require an RSA modulus from 2,048 through 8,192 bits and an odd, bounded public exponent. For `ES256`, require `kty=EC`, `crv=P-256`, and canonical 32-byte base64url x/y coordinates. Reject alg/kty/curve confusion, noncanonical encodings, duplicate IDs and unsupported operations.
7. Select a key using an **exact** `kid` and an explicitly approved, exactly matching `alg`. Never fall back to an unrelated key or algorithm, and never inspect a JWT-provided URL or embedded JWK for candidate keys.
8. All tests are offline with synthetic public parameters. No new runtime dependency or changes to existing ASCA modules, routes or login capabilities.

## Security boundaries and follow-up

- JWKS parsing is **not** JWKS origin verification: byte provenance, TLS, bounded fetch, no redirects/proxies, caching and key rotation require separately reviewed transport and orchestration.
- An EC coordinate pair is **not** asserted to be on the P-256 curve. An RSA modulus is **not** asserted prime-factor-derived. A future cryptographic library must construct and validate the public key and then verify the JWS signature.
- No JOSE protected-header parser is introduced here. The future verifier must reject `alg=none`, HMAC confusion, unsupported `crit` parameters, remote `jku`/`x5u` and embedded `jwk` key substitution.
- Even a correct signature does not confer identity without JWT claims validation: exact issuer, intended audience, nonce, expiry, issued-at time and any required azp rules.
- All domain objects are ordinary Python data and can be manually forged; the types alone cannot grant trusted source provenance, an authenticated principal, or authorization.
- CERN account approval, actual registered client settings and permission to use protected CERN resources remain separate requirements.

## References

- RFC 7517 (JSON Web Key): https://www.rfc-editor.org/rfc/rfc7517
- RFC 7518 (JWA): https://www.rfc-editor.org/rfc/rfc7518
- RFC 8725 (JWT Best Current Practices): https://www.rfc-editor.org/rfc/rfc8725
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- ADR 0011: `0011-oidc-token-response-parser.md`
