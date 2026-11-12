# ADR 0034: Specify independent evidence review and deny-only policy requirements

- **Status:** Proposed for Phase 1A.2.5C4 review
- **Date:** 2026-11-12
- **Depends on:** ADRs 0031–0033 and the C2 evidence register
- **Scope:** Offline policy requirements and negative test vectors only
- **Authority:** No production authorization authority is conferred

## Context

C1 defined ten gates (G1–G10) before ASCA can enable CERN-authenticated
sessions. C2 reviewed CERN registration, MFA/LoA and session requirements.
C3 introduced a strictly non-authoritative intake format with only
`not_supplied` and `submitted_for_review` states for G1, G6 and G7.
An opaque intake reference, even when syntactically valid, is not independent
verification of a CERN registration, positive assurance semantics or a secure
session architecture.

The existing native `ROLE_STATUS=CLAIMED` diagnostic proves the presence of
one scoped role claim in a checked native transaction. It cannot create a
trusted ASCA principal, session or delegated resource access.

## Decision

1. Define an independent review protocol with separate **submission**,
   **technical verification**, **application-owner decision** and **deployment
   security approval** stages. A reviewer's conclusion must be supported by
   source evidence and must not be entered as an authoritative flag in this
   repository. A reviewer must not approve their own submission.
2. Introduce a versioned, **deny-only** set of authorization requirements
   represented by synthetic negative-case vectors. Each case describes a
   boundary violation and an expected `DENY`. There are no positive `ALLOW`
   fixtures and no production authorization engine in this increment.
3. Provide an offline CLI that validates the test-vector structure, rejects
   duplicate members, ambiguous values, unknown cases, unsafe file types and
   oversized input; checks the repository's existing G1/G6/G7 evidence states;
   and prints fixed status labels only. It never calls the CERN network.
4. A zero exit status means **the negative specification and repository
   snapshot are internally consistent**. It does not establish evidence
   authenticity, a reviewer decision, production security, or a successful
   authorization. Every successful invocation must output
   `RESULT=INDEPENDENT_REVIEW_REQUIRED_NO_GRANT`.
5. Preserve the original API status `not_configured`, all capability flags
   disabled and no session, login, access-token, role-grant or chATLAS route.
   The offline CLI is not an application service and must never be imported
   as an authorization adapter.
6. Future server-side policy decisions may be designed only after a separate
   reviewer has independently validated the relevant CERN and deployment
   evidence and a subsequent implementation ADR is accepted. Such decisions
   require additional runtime, integration, distributed-replay and adversarial
   tests; this deny-only specification does not satisfy those requirements.

## Policy requirement classes

| Failure condition | Required behavior | Principal gates |
| --- | --- | --- |
| Forged observation, unverified identity or wrong client | DENY; never promote diagnostic objects | G1, G3, G5 |
| Missing, contradictory, stale or revoked application role | DENY; require active scoped role | G5, G9 |
| Unattested MFA/LoA or insufficient freshness | DENY; no inference from missing-role hints | G6 |
| Replayed/unbound callback or session expiry/revocation | DENY; shared atomic transaction and session controls | G2, G4, G7 |
| Mismatched resource audience/scope or unknown action | DENY; check destination-specific permission | G8 |
| Unreviewed operator intake or skipped deployment gates | DENY; human evidence review remains external | G1, G6, G7, G10 |

All negative cases are synthetic **requirements**. They do not exercise a
production login or claim compliance for a future deployment.

## Independent evidence review protocol

1. **Submit:** the application owner supplies non-sensitive tracking references
   for G1/G6/G7 through a restricted organizational workflow; never commit
   actual screenshots, secrets, tokens or personally identifying records.
2. **Verify:** a distinct authorized security reviewer checks the original
   source/provider contract, client/deployment ownership, effective
   configuration and expiration/freshness. A synthetic record is insufficient.
3. **Decide:** the designated application owner records a documented decision
   and conditions. Disagreement or unavailable evidence means unresolved.
4. **Approve deployment separately:** production change control must assess
   the complete G1–G10 set and an implementation/security test report. Even a
   favorable evidence review does not create an ASCA session or permission.
5. **Revalidate:** configuration changes, compromise, provider-policy changes,
   role revocation or an expired assurance contract invalidate prior review
   assumptions until checked again.

No review result, source identity, signature or approval status is stored in
this repository by C4. The separate restricted workflow owns these records.

## Stop condition and future work

G1, G6 and G7 are not attested in the current repository snapshot. No policy
implementation may return ALLOW until the full trust and authorization
composition has been independently designed, tested and approved. Do not
interpret CLI exit code zero or a complete negative-case suite as an
authorization decision. C4 is not evidence that the missing operator proof
has been acquired.

## References

- ADR 0031: `0031-cern-oidc-authorization-trust-boundary.md`
- ADR 0032: `0032-cern-web-client-assurance-session-review.md`
- ADR 0033: `0033-cern-web-operator-evidence-intake.md`
- C2 evidence register: `docs/security/cern-web-oidc-evidence-register.json`
- C3 intake template: `docs/security/cern-web-operator-intake-template.json`
- OAuth 2.0 Security Best Current Practice: https://www.rfc-editor.org/rfc/rfc9700
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
