# ADR 0036: Separate offline implementation planning from CERN deployment readiness

- **Status:** Proposed for Phase 1A.2.5C6 review
- **Date:** 2026-11-12
- **Depends on:** ADRs 0031–0035 and C2–C5 offline contracts
- **Scope:** Non-authoritative traceability matrix and offline checks only
- **Decision authority:** Future application owner and independent security reviewer

## Context

The native CERN OIDC role observation, including `ROLE_STATUS=CLAIMED`, is not
an authenticated web principal. C2 documented unverified G1/G6/G7 evidence;
C3 introduced non-authoritative intake; C4 specified twenty synthetic DENY
cases; and C5 specified eight stages for a possible future authorization
boundary, with three disabled resource classes. None of those artifacts
implements or attests a production login, session or permission.

Before introducing any enforcement code, the project needs a gate-by-gate
implementation and evidence plan that separates **what can be designed and
unit-tested offline** from **what cannot be approved without provider,
operator, resource-owner and deployment evidence**.

## Decision

1. Add a versioned, ten-item readiness matrix mapping exactly G1–G10 to their
   current C2 repository snapshot, responsible *role*, offline preparation,
   external or deployment evidence, and required verification methods.
2. Each matrix gate remains `blocked`. `partial_offline` or
   `diagnostic_only` describes existing tests, **not** security approval.
   C2's fixed snapshot is not a live CERN status check.
3. Reconcile the matrix against the C2 register, C3 intake template, C4
   negative cases and C5 design contract using a strictly local checker.
   No evidence reference is dereferenced and no external system is contacted.
4. The checker must reject unexpected keys, order changes, inconsistent states,
   forged owner claims, approval values, duplicate JSON members, symlinks,
   unbounded inputs and contradictions with the earlier contracts.
5. Exit status zero means only that the **planning matrix is structurally
   consistent** with the repository's blocked snapshot. The checker must
   return `RESULT=IMPLEMENTATION_REVIEW_REQUIRED_NO_GRANT` and cannot approve
   implementation, deployment, a principal, a session or a resource action.
6. The web BFF registration and assurances require independently reviewed
   CERN information; the distributed session design requires a separate
   architecture approval. Permission policy for ASCA and resource-specific
   consent/audiences/scopes for chATLAS/GitLab require their own review.
7. No API, frontend, credentials, network access, production module, session,
   permission policy, or third-party dependency changes are part of C6.

## Readiness interpretation

| Category | Allowed offline preparation | Required before trusted enablement |
| --- | --- | --- |
| G1, G5, G6 | Negative contracts and synthetic token tests | CERN/owner-verified client, scoped role and positive assurance semantics |
| G2, G3, G4, G7 | BFF, token, replay and session design/test harness | Exact backend deployment, shared storage, browser binding and integration tests |
| G8 | Static resource action matrix and DENY fixtures | Target-service token audience, scope, consent and permission review |
| G9, G10 | Operations and deployment test plan | Incident, key, audit, independent review and deployed-system evidence |

The named evidence-owner roles are **proposed accountability categories**,
not proof that an actual CERN operator or security reviewer has accepted
responsibility or approved any configuration.

## Stop condition

C6 is **not an implementation readiness approval** and not an authorization
policy. G1, G6 and G7 remain blocked; dependent controls remain unapproved.
Do not add a production `ALLOW` path, login, authentication cookie, tool
permission, token forwarding, chATLAS operation or CERN GitLab access based on
this matrix, its successful tests, or a generated report. Any future
implementation requires a new approved ADR and independent live evidence
review of the relevant G1–G10 controls.

## References

- ADR 0031: `0031-cern-oidc-authorization-trust-boundary.md`
- ADR 0032: `0032-cern-web-client-assurance-session-review.md`
- ADR 0033: `0033-cern-web-operator-evidence-intake.md`
- ADR 0034: `0034-independent-evidence-review-and-negative-policy-spec.md`
- ADR 0035: `0035-cern-web-authorization-decision-contract.md`
- C2 register: `docs/security/cern-web-oidc-evidence-register.json`
- C5 design: `docs/security/cern-web-authorization-decision-contract.json`
