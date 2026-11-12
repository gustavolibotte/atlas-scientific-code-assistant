# CERN web authentication: independent evidence review protocol (C4)

**Scope:** process and negative-policy requirements only. No live CERN
connection, attestation, login, production session or authorization grant.

## Responsibilities and separation of duties

| Role | Responsibility | Not sufficient on its own |
| --- | --- | --- |
| Evidence submitter | Provide restricted-source references for G1, G6 and G7 | A self-authored declaration cannot prove a deployment |
| Independent security reviewer | Verify source authenticity, effective settings, assurance semantics and control ownership | A documentation snapshot cannot prove an active configuration |
| Application owner | Decide whether proposed requirements and residual risks are acceptable | Owner acceptance does not substitute for implementation tests |
| Deployment reviewer | Check G1–G10 together against the exact deployed code/configuration | Passing offline tests cannot authorize production release |

Reviewers must be distinct from the evidence submitter for the item they
review. Record conflicts of interest and escalation outside the repository.
The restricted review record needs an accountable approver, review date,
source provenance, changes covered, expiration/re-review trigger and unresolved
conditions. Do not transmit the underlying private records in issues or CI.

## G1: independently confirm web-client registration

Confirm a separate CERN web/BFF registration, owner, client type and supported
authentication method. Verify the exact HTTPS callback, grant types, scopes,
issuer/audience and deployment-controlled hostname against the actual provider
registration. Do not reuse the `asca-glibotte-dev` native/loopback client as
an authenticated web trust root. Do not submit client secrets.

## G6: independently confirm MFA/LoA assurance

Obtain CERN-authoritative semantics for positive MFA/LoA enforcement and
freshness, including role-policy guarantees or signed `amr`/`acr`/`auth_time`
semantics when formally documented. **Never** infer that assurance is met merely
because `cern_roles_missing_mfa` or `cern_roles_missing_loa` is absent. Specify
what fails closed on missing/contradictory claims, stale assurance, downgrade,
logout and role withdrawal. Require a reviewer-approved contract, not a sample
token pasted into an issue.

## G7: independently confirm session controls

Review a server-owned, shared atomic transaction store, cookie `HttpOnly`,
`Secure` and `SameSite` attributes, CSRF protection, session identifier
rotation, idle and absolute expiration, logout, revocation, distributed state,
clock failures, audit minimization, key rotation and incident invalidation.
Assign owners and explicit numerical values only in a separately approved
configuration/ADR. An application session does not follow from a native OIDC
diagnostic or a successful intake record.

## G8–G10: do not conflate with G1/G6/G7

External CERN resources require independent audience, scopes, consent,
permission and revocation checks. The entire G1–G10 deployment gate set
requires its own technical and security verification. No ID Token may be
forwarded as an API access token merely because CERN SSO succeeded.

## Negative policy requirement cases

`docs/security/cern-web-negative-policy-cases.json` lists synthetic threats
and expected `DENY` decisions. `scripts/check_cern_web_negative_policy.py`
checks schema and cross-document coherence; **it is not a policy runtime**.
The fixture deliberately has no successful authentication, authorization or
session case. Its zero exit code means only a valid deny-only specification.

Required review questions before any future implementation:

1. What CERN-owned evidence verifies the distinct web client and who attests it?
2. What precise signed provider evidence establishes MFA/LoA and freshness?
3. What session design, TTLs and revocation guarantees were reviewed?
4. What resources/actions are permitted and which token audiences are valid?
5. Which independent test suite proves the controls in the intended deployment?

**Current answer:** the repository does not contain these approvals. Keep
ASCA login, role authorization, sessions and chATLAS disabled.
