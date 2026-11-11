# ADR 0030: Observe CERN native OIDC roles within one consumed code exchange

- **Status:** Proposed for Phase 1A.2.5B3 review
- **Date:** 2026-11-11
- **Scope:** Opt-in diagnostic only; no identity, login, role authorization or session
- **Depends on:** ADRs 0027, 0028 and 0029

## Context

Phase 1A.2.5A proved the native public-client CERN authorization-code and PKCE
exchange with signature, issuer, audience, nonce, expiry and `at_hash` checks.
Phase 1A.2.5B1 added strict offline role inspection. Phase 1A.2.5B2 composed
role inspection after one pinned CERN JWKS/JWS/claims verification. However,
no native authorization transaction currently invokes that operation.

The configured application `asca-glibotte-dev` has an intended role
`asca-developer`. The actual role-claim shape for a real CERN login remains
unverified; no actual role evidence may be assumed from a synthetic test.

## Decision

1. Preserve the current native `exchange_callback` API, callback lifecycle
   `complete`, and existing opt-in ID-token diagnostic behavior. Add a
   **separate** `exchange_callback_observe_role`, callback lifecycle
   `complete_role_observation`, and CLI `check_cern_oidc_native_role_live.py`.
2. Share the original atomic authorization-attempt consumption, PKCE token
   request, HTTPS token exchange, and bounded token-response parser. Select
   precisely one verifier operation: existing `check` or the new
   `observe_role`. Do not issue two token endpoint requests, fetch JWKS twice,
   or allow a second callback exchange for the same authorization attempt.
3. Fix the expected role in the native diagnostic composition to
   `asca-developer`. No caller-supplied token, JWKS, verifier, role name or
   signing-key material enters the native callback interface.
4. Reuse the existing strict loopback callback parser, private browser-binding
   state, allowed CERN issuer, error denial consumption and single-use
   token-exchange behavior. The CLI calls the already-reviewed default-only
   discovery/bootstrap and transport, not test adapters.
5. Keep live execution **opt-in via `--live`**. Offline invocation must not
   bind a socket, open a browser, fetch CERN metadata or exchange tokens.
   Automated tests and CI use synthetic collaborators without CERN network.
6. Print fixed non-sensitive status labels only: `CLAIMED`, `ABSENT`,
   `MFA_REQUIRED`, `LOA_REQUIRED`, `MFA_AND_LOA_REQUIRED`. Do not print ID or
   access tokens, authorization URL, callback query, state, PKCE verifier,
   nonce, subject, user name, email, group, role lists, JWT claims or errors
   originating from HTTP/provider responses.
7. Treat all role statuses, including `CLAIMED`, as **observation only**.
   Missing roles and MFA/LoA restrictions are not authorization grants. No
   ASCA principal, session, permission, login route, token persistence or
   chATLAS capability is created. Every terminal path revokes pending native
   authorizations and closes the local listener.
8. Add offline unit and security tests for original-flow compatibility,
   denial and replay protection, error sanitization, role-status validation,
   explicit opt-in, and fixed output. CI must never perform a live login.

## Limitations and follow-up

- Native bootstrap and Python in-process types are **not a production login
  trust root**; this diagnostic cannot attest official registration to a
  future API session, multi-process replay guarantees, role revocation or
  continuous MFA/LoA compliance.
- Role claims could be missing or different in the real ID Token. An explicit
  authorized operator must run the live diagnostic after offline review. If
  rejected, report only fixed labels; any follow-up should diagnose claim
  shape privately, without exposing actual tokens or identity data.
- A `ROLE_STATUS=CLAIMED` result is evidence that this one local transaction's
  checked ID Token carried the requested claim, not proof of authorization.
- Production-grade user authentication, role policy, MFA/LoA assurance,
  sessions, credential storage, role revocation, and CERN resource access are
  separate reviewed security milestones.

## References

- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 8252: https://www.rfc-editor.org/rfc/rfc8252
- RFC 9700: https://www.rfc-editor.org/rfc/rfc9700
- ADR 0027: `0027-opt-in-cern-native-live-verification-diagnostic.md`
- ADR 0029: `0029-verified-cern-oidc-role-observation.md`
