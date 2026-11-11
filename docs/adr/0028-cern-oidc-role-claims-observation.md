# ADR 0028: Observe CERN application-scoped OIDC role claims without granting access

- **Status:** Proposed for Phase 1A.2.5B1 review
- **Date:** 2026-11-11
- **Scope:** Deterministic, offline claims policy; no login or access decision
- **Depends on:** ADRs 0016, 0017 and 0027

## Context

Phase 1A.2.5A successfully exercised an opt-in real CERN native public-client
Authorization Code + PKCE exchange, including signature, nonce, issuer,
audience, expiry and `at_hash` checks. It deliberately made no role decision.
The registered application is `asca-glibotte-dev`; its restricted group is
`asca-glibotte-dev-users`, and its role identifier is `asca-developer`,
with CERN LoA and MFA requirements configured in the CERN Applications Portal.

CERN documentation states that application roles can appear under
`resource_access.{application_name}.roles` in Access and ID tokens.
`cern_roles` is a duplicate of the application role list. The optional arrays
`cern_roles_missing_loa` and `cern_roles_missing_mfa` identify roles withheld
because the current login did not meet the application policy. Missing
`resource_access` means no roles for that application; claims may be omitted
or extended as CERN SSO evolves.

## Decision

1. Introduce a pure, offline role-claims observation function that consumes the
   same signature-checked (but **forgeable**) payload wrapper used by the OIDC
   claims validator. Run existing issuer, audience, nonce, timestamp, and
   optional access-token `at_hash` checks before inspecting role fields.
   Reuse the existing strict JSON decoder to reject duplicate members.
2. Require an explicitly expected client ID and role identifier. Inspect **only**
   `resource_access[expected_client_id].roles`; never authorize using realm
   roles, groups, `preferred_username`, email, arbitrary extensions, or a role
   belonging to another application.
3. Validate bounded, duplicate-free lists with strictly defined role identifier
   syntax. If `cern_roles` is supplied, require it to agree with the scoped
   roles; never use it as an independent source of a grant. Ignore unrelated
   resource entries rather than promoting or normalizing them.
4. Treat the documented `cern_roles_missing_mfa` and
   `cern_roles_missing_loa` entries as **denial hints**, never as assertions
   that MFA or LoA requirements were met. When the target role is both granted
   and marked missing, reject the contradictory token structure.
5. Return an immutable `UntrustedCernRoleObservation` with a status from
   `claimed`, `absent`, `mfa_required`, `loa_required` or
   `mfa_and_loa_required`. All results have `authorization=not_implemented`
   and `login=not_implemented`. Even `claimed` is **not** a capability.
6. Never return subject, token, role identifiers, groups or other private
   claims. Sanitize errors. Do not add network access, API routes, sessions,
   principals, database changes, third-party dependencies or chATLAS actions.
7. Add positive, negative, malformed, scope-confusion, contradictory-role and
   secret-handling regression tests; all automated tests must run offline.

## Deliberate limitations and next step

- An arbitrary Python caller can fabricate the `SignatureCheckedUntrustedOidcPayload`,
  the client ID, and the nonce. **This module cannot attest CERN identity or
  authorize anything.** A future increment must invoke role checks *inside*
  the trusted verification and single-use native transaction composition,
  without accepting externally supplied verified-token wrappers.
- Whether the registered role actually appears in the operator's real CERN
  ID Token remains unverified; the documentation describes the contract, not
  the result of this account's login. A future opt-in, sanitized live probe
  must check its presence before granting any application permission.
- Roles may change after a token is issued; role revocation, refresh policies,
  access-token versus ID-token trust, session lifetime and MFA/LoA freshness
  require distinct designs. Presence of a role alone must not imply that ASCA
  is ready to create a session or access CERN/ATLAS resources.
- No public login route, CERN SSO session, or chATLAS access is enabled.

## References

- CERN Authentication and Authorization Service, *OIDC configuration and usage*,
  operator-provided PDF (2026-11-11), pages 1–3.
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 8725, JWT Best Current Practices: https://www.rfc-editor.org/rfc/rfc8725
- ADR 0027: `0027-opt-in-cern-native-live-verification-diagnostic.md`
