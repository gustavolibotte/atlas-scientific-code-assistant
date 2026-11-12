# ADR 0032: Review CERN web-client, assurance and session prerequisites

- **Status:** Proposed for Phase 1A.2.5C2 review (design-only)
- **Date:** 2026-11-11
- **Depends on:** ADR 0031, ADR 0030
- **Decision authority:** Application owner and security reviewer; no deployment approval here

## Context

Phase 1A.2.5B3 observed the `asca-developer` claim in a single authorized,
native/public-client transaction for `asca-glibotte-dev`. Phase 1A.2.5C1
listed ten mandatory authorization/deployment gates. The checked native token
and `UntrustedCernRoleObservation` remain forgeable diagnostic objects and are
not authorization or web-session evidence. The FastAPI application currently
reports CERN login as not configured.

This ADR narrows the open requirements for **web client registration (G1)**,
**assurance semantics (G6)**, **server-side sessions (G7)** and the dependencies
G2–G5, G8–G10. It does **not** approve any deployment, enable access, or
implement an authorization decision.

## Evidence classification

1. **Repository-observed:** source contracts, diagnostics, and PR #28 native
   result (`CLAIMED` in a single test). These do not attest a web client.
2. **CERN documentation snapshot:** operator-supplied public CERN guidance,
   saved on 2026-11-11; documents describe provider configuration rather than
   ASCA deployment evidence. The live documentation URLs can be inaccessible
   from some environments; a saved snapshot is not a provider attestation.
3. **Reference application example:** published CERN-hosted application
   instructions, informative only and not an ASCA registration record.
4. **Security requirement:** ASCA design decision or OAuth/OIDC security rule,
   not evidence that a control has already been implemented.
5. **Operator attestation:** future verified configuration/evidence for the
   proposed ASCA web deployment; currently **not available**.

The traceable entries are recorded in
`docs/security/cern-web-oidc-evidence-register.json` and summarized in
`docs/security/cern-web-oidc-review.md`.

## G1 — Web/OIDC client and registration

- **Selected architecture for design:** a server-side web BFF, rather than
  reusing the existing native loopback/public-client diagnostics. This is a
  proposed target, not an active deployment. Keep any client credentials on
  the backend only. The public React frontend must never receive credentials
  or act as a trusted token verifier.
- The official CERN SSO registration example distinguishes clients that
  **cannot safely store a client secret** (public clients) from those that can.
  The operator must verify the actual web application type, credential method,
  allowed grant types, authorized scopes, client identifier and owner in the
  CERN Applications Portal. Do **not** infer these settings from a sample form.
- Require an exact HTTPS redirect URI and an explicit deployment hostname;
  no wildcard callback, native loopback URI or front-end-only callback may be
  silently promoted to a production web login.
- The portal also exposes a separate client-credentials option for services
  acting on their own behalf. Do not enable it merely to support interactive
  user login. Delegated service-to-service access requires a separate decision.
- Do not register or alter a CERN application, request a client secret or
  commit configuration values as part of this increment.

## G6 — MFA / Level of Assurance

- CERN documentation describes application roles under
  `resource_access[client_id].roles`. It also describes
  `cern_roles_missing_mfa` and `cern_roles_missing_loa` as roles withheld
  because of unmet restrictions. These are **denial hints**, not positive
  proof of the authentication factors or LoA actually satisfied.
- No reviewed CERN-specific mapping of affirmative `amr`, `acr`, `auth_time`,
  or an equivalent signed assurance attestation has been established for ASCA.
  **Do not invent a mapping**, even if an example token appears to contain
  a promising claim.
- Before the first policy implementation, the owner/security reviewer must
  establish whether CERN's application-role enforcement itself constitutes
  sufficient **provider-attested** MFA/LoA evidence for the ASCA threat model,
  or whether signed, freshness-bound positive claims are required. This needs
  official provider guidance and an explicit review decision; default DENY.
- Require defined reauthentication intervals, assurance downgrade handling,
  logout effects, and separate resource-server policy. A role observation is
  not ongoing assurance.

## G7 — Web session and transaction lifecycle

- Session establishment, storage and rotation are **not implemented**. A
  future BFF requires a server-owned login transaction, per-browser binding,
  CSRF protections, PKCE, signed-token verification and atomic single-use
  callback handling across workers. Do not copy the native process-local store.
- Use an opaque, cryptographically random session identifier carried via an
  `HttpOnly`, `Secure` cookie with reviewed `SameSite`, path/domain and CSRF
  rules. No access/ID/refresh token may enter localStorage, sessionStorage,
  browser JavaScript, LLM prompts or telemetry.
- Specify idle and absolute TTLs, rotation after login and privilege changes,
  logout, revocation, signing/encryption key lifecycle, multi-instance store
  consistency, clock handling and emergency invalidation **before** code.
  No numeric TTL is asserted by this ADR; the owner must approve a concrete
  risk-based policy in a separate increment.
- CERN OIDC guidance discusses end-session behavior and cautions against
  forcibly logging out users from SSO. Application logout/expiry must be
  independently enforced; whether to offer optional SSO logout needs review.

## Required web login transaction sequence (design only)

1. Obtain server-owned client/deployment configuration and verify an exact,
   registered HTTPS callback.
2. Start a bound, short-lived, single-use authorization transaction with
   state, nonce and PKCE S256; protect cookies against login CSRF.
3. On the callback, validate provider issuer, state/binding, code and redirect;
   atomically consume the transaction in a shared store.
4. Exchange the code from the backend with the registered client mechanism;
   verify token signature, issuer, audience/azp, nonce, validity and `at_hash`
   as applicable. Fail closed on provider/clock/metadata ambiguity.
5. Derive a server-owned authenticated subject **only** from that trusted
   composition; do not import diagnostic result objects into this boundary.
6. Perform an independent application role and assurance decision using
   provider-reviewed positive evidence and the exact registered client role.
7. If and only if all gates are approved, issue a new server-side session;
   enforce CSRF, revocation and permission checks on every protected action.
8. Check delegated access to chATLAS/GitLab independently with dedicated
   resource audience/scope and permission requirements.

This sequence is a design proposal, not an instruction to deploy it now.

## Decisions intentionally UNRESOLVED

- Actual CERN web-client registration and ownership, callback hostname,
  secret storage and rotation authority.
- Whether the chosen client registration supports confidential exchange and
  the precise supported authentication method.
- CERN-authoritative positive MFA/LoA semantics, role-restriction enforcement
  guarantees, and freshness/revocation guarantees.
- Session-store technology, cookie policy, TTL, logout UX, distributed
  invalidation and audit data-retention policy.
- Separate chATLAS/GitLab audiences, delegated consent and per-operation
  access controls.

**Stop condition:** no login/session/permission implementation or ASCA
capability/status change is permitted while these decisions are unresolved.

## Scope and next increment

Only documents, a structured evidence register, and offline negative tests are
added in C2. No production changes, new endpoint, network call, credentials,
CERN registration, real login, session or chATLAS capability. A future C3
should review operator-approved requirements before a standalone, offline
policy specification or a separate BFF bootstrap prototype is considered.

## References

- ADR 0031: `0031-cern-oidc-authorization-trust-boundary.md`
- CERN *Registering your application to SSO*, saved public documentation
  (2026-11-11): https://auth.docs.cern.ch/applications/sso-registration/
- CERN *OIDC configuration and usage*, saved public documentation
  (2026-11-11): https://auth.docs.cern.ch/user-documentation/oidc/config/
- CERN *Configuring your application*, saved public documentation
  (2026-11-11): https://auth.docs.cern.ch/applications/application-configuration/
- CERN CAiMIRA deployment (independent published example):
  https://caimira.docs.cern.ch/root/deployment/
- RFC 9700: https://www.rfc-editor.org/rfc/rfc9700
- RFC 8252: https://www.rfc-editor.org/rfc/rfc8252
- OIDC Core: https://openid.net/specs/openid-connect-core-1_0.html
