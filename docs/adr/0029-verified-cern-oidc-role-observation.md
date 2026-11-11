# ADR 0029: Compose CERN role observation after pinned JWKS/JWS/claims checks

- **Status:** Proposed for Phase 1A.2.5B2 review
- **Date:** 2026-11-11
- **Scope:** Isolated offline verification composition; no login, session, role grant or live role probe
- **Depends on:** ADRs 0017, 0027 and 0028

## Context

Phase 1A.2.5B1 introduced strict observation of application-scoped role claims,
but its `SignatureCheckedUntrustedOidcPayload` argument can be constructed by
any Python caller. Even a `claimed` result must not be used as evidence of
actual CERN roles. Meanwhile, `CernOidcVerificationPipeline.check` already
performs ordered metadata, pinned JWKS, JWS-signature and OIDC claims checks.
The live native code exchange is separate and must not be altered here.

## Decision

1. Refactor the verification pipeline's existing `check` implementation to
   share one private `_verified_payload` method that returns the signature and
   claims results from **one** pinned JWKS retrieval. Preserve the public
   `check` signature, default policies, return shape, and error sanitization.
2. Add a separate `observe_role` method that obtains the checked payload only
   by invoking `_verified_payload` itself; never accept caller-supplied
   parsed JWKS, signed-payload wrappers, or role observation results.
3. Apply the existing `inspect_untrusted_cern_application_role` policy to the
   **same** newly verified payload, with the exact expected client ID, nonce,
   clock and access token. The latter keeps optional `at_hash` bound to the
   token endpoint response. The role policy re-validates OIDC claims.
4. In the role-specific method, fix the existing strict 60-second clock skew,
   3600-second lifetime and **no additional audiences**. Do not silently infer
   or widen audience allowlists or import role names from token fields.
5. Return only `UntrustedCernRoleObservation` with statuses including
   `claimed`, `absent`, and MFA/LoA restriction markers. No subject, token,
   signing key ID, bearer credential or role name is returned in that result.
6. Map invalid role structures to secret-free `OidcVerificationError`, fail
   closed for missing or inconsistent roles and retain existing fail-closed
   response/cryptography controls.
7. Cover real ephemeral RSA/P-256 JWS signatures for RS256, PS256 and ES256,
   valid/absent/restricted roles, failure ordering, one-fetch invariant,
   malformed input, wrong nonce/audience, wrong access-token hash, and
   non-authoritative return type. All tests are offline.

## Deliberate limitations and next work

- This method still receives `tokens`, metadata, client ID, nonce and clock from
  Python callers. Injected fetchers and monkeypatches remain possible.
  **It is not a trusted CERN identity or authorization root**.
- It does not consume a browser-bound authorization attempt, create a principal,
  authorize `asca-developer`, enable a session, or integrate with chATLAS.
- The CERN ID Token's actual role-claim shape remains unverified in live tests.
  A later, explicitly opt-in increment must connect this observation to the
  single-use native exchange and emit only sanitized role-status labels.
- No API routes, startup hooks, network-capable diagnostic, new dependency or
  database model is introduced by this change.

## References

- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 8725: https://www.rfc-editor.org/rfc/rfc8725
- ADR 0027: `0027-opt-in-cern-native-live-verification-diagnostic.md`
- ADR 0028: `0028-cern-oidc-role-claims-observation.md`
