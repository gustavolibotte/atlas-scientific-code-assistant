# ADR 0035: Specify a non-authoritative CERN web authorization decision contract

- **Status:** Proposed for Phase 1A.2.5C5 review
- **Date:** 2026-11-12
- **Depends on:** ADRs 0031–0034 and the G1–G10 evidence register
- **Scope:** Design-only contract, offline validation and adversarial tests
- **Decision authority:** Future application owner and independent security reviewer

## Context

C1–C4 established the separation between a native CERN role *observation*,
web-client trust, provider-supported MFA/LoA assurance, server sessions, external
resource permission and independently reviewed deployment. C4 records 20
synthetic `DENY` cases; it is not a runtime authorization implementation.
The current web-client registration (G1), affirmative assurance semantics (G6)
and session controls (G7) remain unverified. This increment **does not resolve**
those missing requirements or enable login.

## Decision

1. Introduce one versioned, machine-readable **design contract**, never an
   executable application policy or a signed authorization record.
2. Enumerate eight independent required checks covering **G1–G10**. Each stage
   denies when required evidence is missing. A future successful decision is
   **out of scope**; the design contract contains only `DENY`, not `ALLOW`.
3. Distinguish server-attested subject and exact web client from diagnostic
   `UntrustedCernRoleObservation` and caller-constructed token wrappers.
   Diagnostic result objects are not authorized principals.
4. Require a provider-reviewed, positive MFA/LoA and freshness contract;
   absent `cern_roles_missing_mfa`/`cern_roles_missing_loa` hints do not prove it.
5. A future server-owned session must be independently bound to the requesting
   browser, unexpired, unrevoked, and checked per protected operation. A role
   claim or successful OIDC callback does not constitute a current session.
6. Separate ASCA workspace permission from chATLAS and CERN GitLab. External
   services have distinct access-token audience, scopes, user consent and
   resource-side authorization. Do not forward an ASCA ID Token as an API token.
7. Define required *future* context and decision-envelope field names, but do
   not serialize actual identity attributes, token values, sessions or secrets.
8. Supply a local, stdlib-only checker of the **exact design** and the blocked
   C2/C3/C4 repository snapshots. A successful checker run must say
   `RESULT=INDEPENDENT_REVIEW_REQUIRED_NO_GRANT` and never mean ready or approved.
9. Keep the existing ASCA API identity status `not_configured`. Do not modify
   production modules, routes, frontend, dependencies or application settings.

## Proposed future decision processing (not implemented)

A server-owned authorization boundary would obtain authenticated subject
provenance and enforce the stage sequence. Each stage requires independent
trustworthy evidence or produces `DENY`. Unknown resource, action, role,
provider semantics, timestamp, token audience, session state or review status
must fail closed. The response envelope must not include tokens or credentials.

| Stage | Required check | Gates |
| --- | --- | --- |
| Web client binding | Exact registration, HTTPS backend and browser binding | G1, G2 |
| Trusted OIDC transaction | Valid signed exchange and atomic single-use callback | G3, G4 |
| Application role | Reviewed exact-client application-scoped role | G5 |
| Positive assurance | Authoritative MFA/LoA and freshness | G6 |
| Active session | Server-owned expiry, rotation, revocation and CSRF | G7 |
| Resource permission | Separate resource audience, scopes, action and consent | G8 |
| Operations | Role refresh, keys, incidents and policy changes | G9 |
| Release security | Independent G1–G10 deployment review | G10 |

No stage can be satisfied by a source-controlled JSON assertion, operator
tracking reference, CI result or a locally constructed Python object alone.
The future implementation requires a separate approved ADR and integration
verification before enabling any `ALLOW` path.

## Distinct ASCA/resource boundaries

- **ASCA workspace:** CERN authentication and role checks alone do not grant
  action permissions. Specific operations require explicit application policy.
- **chATLAS:** a dedicated resource token, audience/scope and per-operation
  policy must be confirmed separately.
- **CERN GitLab:** a distinct audience, permissions, user consent and
  revocation model must be reviewed separately.

A future positive authorization path, policy revision/versioning and live
integration are deliberately deferred. The design is not provider evidence.

## Stop condition

`G1=BLOCKED`, `G6=BLOCKED`, `G7=BLOCKED` remain the repository position. No
C5 script evaluates a real user, grants ASCA access, issues a cookie/session,
performs a CERN network request or reaches chATLAS. **STOP** on any attempted
promotion from offline fixtures to authorization authority.

## References

- ADR 0031: `0031-cern-oidc-authorization-trust-boundary.md`
- ADR 0032: `0032-cern-web-client-assurance-session-review.md`
- ADR 0033: `0033-cern-web-operator-evidence-intake.md`
- ADR 0034: `0034-independent-evidence-review-and-negative-policy-spec.md`
- C4 negative cases: `docs/security/cern-web-negative-policy-cases.json`
- OAuth 2.0 Security BCP: https://www.rfc-editor.org/rfc/rfc9700
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
