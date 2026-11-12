# CERN web authentication: C6 implementation prerequisite review

This is a planning and traceability document, **not a security approval**.
The C2 repository snapshot describes the status of documented work, not the
live state of any CERN Applications Portal registration.

## Work that can proceed offline

- Define a trusted BFF interface and synthetic authorization state machine,
  keeping test adapters and constructed identity objects non-authoritative.
- Design cryptographic OIDC verification boundaries, exact-client role parsing,
  one-time callback consumption, multiworker replay tests and failure handling.
- Specify and test DENY paths for missing assurance, stale role, expired or
  revoked session, unknown action and mismatched resource audience/scope.
- Create isolated test harnesses for session TTL/rotation, CSRF, logout and
  cross-worker invalidation. These may **not** be connected to protected ASCA
  endpoints before deployment prerequisites are independently reviewed.
- Maintain a traceability table from G1–G10 to applicable offline tests,
  integration tests, operations exercises and owners.

## Evidence required outside this repository

| Gate | Review prerequisite |
| --- | --- |
| G1 | Independent check of separate CERN web-client registration, exact HTTPS callback, grants, issuer, approved scopes and accountable owner |
| G6 | CERN-authoritative **positive** MFA/LoA semantics, freshness, role-policy guarantees and fail-closed downgrade behavior |
| G7 | Approved session and transaction storage, idle/absolute TTL, browser cookie policy, revocation, CSRF, multiworker consistency and operator ownership |
| G8 | Actual resource-owner confirmation of ASCA actions and distinct chATLAS/GitLab audience, scope, consent and permission requirements |
| G9–G10 | Independent operational/deployment assessment and incident response exercises on the final architecture |

Other gates G2–G5 also require implementation and integration evidence. A
native `ROLE_STATUS=CLAIMED` diagnostic cannot satisfy G1, G5, G6 or G7.
Missing `cern_roles_missing_mfa` / `cern_roles_missing_loa` arrays do **not**
provide affirmative assurance. No tokens, secrets, claims, screenshots or
personal information should be committed or shared in normal diagnostics.

## Prioritised external decisions

1. Decide who owns an appropriate CERN web-client registration and obtain
   independently reviewed, **non-secret** details of client class and callback.
2. Request official positive MFA/LoA semantics and authentication freshness
   guarantees from CERN, without collecting user identity tokens in issues.
3. Decide a reviewed BFF deployment topology and concrete session policy,
   including distributed transaction storage, idle/absolute TTL and revocation.
4. Obtain resource-specific ASCA/chATLAS/GitLab access-policy review.
5. Only then create a **separately approved implementation ADR** and require
   appropriate negative integration, concurrency, end-to-end and security
   tests before any protected runtime feature is enabled.

## Interpretation of the CLI

`python scripts/check_cern_web_implementation_readiness.py` validates the
versioned traceability matrix and the static C2/C3/C4/C5 repository artifacts.
It does not query CERN, inspect actual evidence, validate any role, authorize
an action or issue a session. A successful result means the **offline plan is
coherent**, never that implementation or deployment is approved.

All ten gate rows remain `blocked`. G1/G6/G7 specifically retain the C2
states `not_attested`, `not_attested`, and `not_implemented`. The 20 C4 DENY
scenarios and three disabled C5 resources remain unchanged.
