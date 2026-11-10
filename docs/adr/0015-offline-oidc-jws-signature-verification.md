# ADR 0015: Check OIDC compact JWS signatures without establishing identity

- **Status:** Proposed for Phase 1A.2.4D review
- **Date:** 2026-11-10
- **Scope:** Offline RS256, PS256 and ES256 signature verification against supplied, unverified-provenance public JWKS

## Context

PR #9 introduced an unverified OIDC token-response parser. PR #10 introduced a strict CERN JWKS declaration parser and exact `kid`/algorithm selection. PR #11 introduced a deliberately unmounted HTTPS JWKS fetcher. PR #12 added public-key construction using PyCA `cryptography`, without claiming CERN provenance. A cryptographic JWS signature check must not silently promote these intermediate contracts to an authenticated identity or trust user-supplied JOSE key locations.

## Decision

1. Introduce `verify_untrusted_oidc_jws_signature` as an **offline**, unmounted verifier. It receives `ParsedUnverifiedOidcTokenResponse` and `ParsedUnverifiedOidcJwks`, and constructs an approved public key with the existing `construct_cern_oidc_public_key` boundary. It never fetches keys or derives a trust anchor from JWT input.
2. Accept only nonempty three-part compact JWS representations, with overall 32,768-character limit, canonical unpadded base64url segments and bounded decoded header, payload and signature sizes. Reject detached/unencoded payloads, compressed representations and noncanonical encodings.
3. Parse only the **protected** JOSE header with strict UTF-8 JSON, duplicate-member detection at any depth and rejection of nonstandard numeric constants. Require exactly approved `alg` (`RS256`, `PS256` or `ES256`) and an exact, safe `kid`. The only optional header is `typ=JWT` (case-sensitive). Reject unknown or unreviewed headers, including `none`, HMAC, `crit`, `b64`, `jwk`, `jku`, `x5u`, `x5c`, and certificate thumbprints.
4. Require algorithm and `kid` to match the selected public JWK declaration exactly; prevent RSA/EC substitution, algorithm fallback and mixed-key confusion.
5. For `RS256`, use RSA PKCS#1 v1.5 with SHA-256. For `PS256`, use RSA-PSS with SHA-256, MGF1(SHA-256) and **exactly 32-byte salt**. Require RSA signature length equal to the modulus length.
6. For `ES256`, require an EC P-256 public key and the JWS-required **64-byte raw `R || S`** signature. Reject zero/out-of-range scalars and use the cryptography backend to verify the converted DER signature with ECDSA(SHA-256).
7. Return only `SignatureCheckedUntrustedOidcPayload` containing `alg`, `kid` and opaque signed payload bytes, hidden from `repr`. There is no claims interpretation, principal, session, access token, authorization or trust-provenance claim.
8. Map expected failures to `OidcJwsError` without echoing JWTs, keys, claims or backend exception messages. All tests run offline with synthetic **ephemeral private keys generated in memory**; no real CERN or ATLAS data, persistent test signing keys or network access.

## Security boundaries and limitations

- The public JWKS dataclass is **not provenance-attested**. Passing an attacker-supplied public key and attacker-signed token can produce a mathematically correct signature result. Future orchestration must bind pinned, TLS-verified retrieval to parsing, key selection, signature verification and key-rotation policy before trusting a result.
- An apparently well-formed and validly signed payload may contain false, stale, misdirected or malicious claims. The next increment must parse strict JWT claims and validate exact issuer, client audience, nonce, `exp`, `iat`, `nbf` policy and `azp` rules before promoting identity.
- The payload is intentionally **not required to be JSON** at this stage. The strict OIDC claims validator will reject unsuitable content.
- The `SignatureCheckedUntrustedOidcPayload` dataclass is ordinary forgeable Python data. The type name does not constitute an authentication capability or trusted provenance.
- No real CERN sign-in, JWT verification route, token cache, user session, or permission check is enabled. The production `cern_sso` state remains `not_implemented`.
- Some otherwise legal JOSE protected-header extensions and encrypted/nested tokens are intentionally unsupported. Provider compatibility must be reviewed before any live deployment.

## References

- RFC 7515 (JWS): https://www.rfc-editor.org/rfc/rfc7515
- RFC 7518 (JWA): https://www.rfc-editor.org/rfc/rfc7518
- RFC 8725 (JWT Best Current Practices): https://www.rfc-editor.org/rfc/rfc8725
- ADR 0012: `0012-oidc-jwks-public-key-trust-boundary.md`
- ADR 0013: `0013-cern-jwks-https-retrieval.md`
- ADR 0014: `0014-oidc-cryptographic-public-key-construction.md`
