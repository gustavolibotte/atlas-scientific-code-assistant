# CERN web authorization contract review — C5

**Classification:** offline architecture artifact, not provider attestation or
production access policy.

## Trust and evidence provenance

- CERN published OIDC documentation describes capabilities, not a registered
  ASCA web application or deployed client configuration.
- A native `ROLE_STATUS=CLAIMED` diagnostic is not a server-authenticated ASCA
  subject. Caller-created checked objects are likewise non-authoritative.
- C3 `EVIDENCE-1234` references are opaque tracking IDs. They do not indicate
  verified client registration, assurance or session architecture.
- C4 negative cases are **requirements**, not evidence that real middleware
  rejects the attacks.

## Required future input boundary

A future trusted policy composition (not implemented) must obtain from server
controls: an authenticated subject and exact registered web-client identity;
valid nonce/state/PKCE/one-use transaction provenance; current exact-client
role; affirmative provider assurance with freshness; active server-side
session; target resource/action; resource-specific token permission; and
independently verified deployment/security evidence.

Input must never be constructed from untrusted browser claims or passed in by
an LLM. Missing, ambiguous, stale, revoked, mismatched or unreviewed fields
require `DENY`. The optional context field names in the JSON contract are
**not** a JSON format accepted by any production endpoint.

## Decision envelope requirements

The eventual server-side decision must be auditable through a non-sensitive
reason code, policy revision and correlation ID, while avoiding credentials,
JWT claims, session cookies, source identity records or personal identifiers
in diagnostics or LLM prompts. A local checker cannot create such a decision.

C5's `design_decision_values` intentionally contains **only** `DENY`.
A later `ALLOW` design requires explicit policy definitions, owner-approved
resource action mapping, provider assurance, live integration security review
and a separate increment. Do not extend C5 by merely adding `ALLOW` in JSON.

## Review requirements before implementation

1. Independently attest CERN web-client registration and deployment boundary
   for G1/G2, separate from the native/public client.
2. Obtain positive provider-authoritative MFA/LoA freshness semantics for G6.
3. Approve numerical session TTLs, CSRF, atomic replay storage, rotation,
   logout, emergency invalidation and credential/key ownership for G7.
4. Approve explicit ASCA actions, chATLAS and GitLab delegated audiences,
   scopes, consent and ongoing revocation behavior for G8/G9.
5. Complete independent deployment and adversarial G1–G10 security review.

Until those conditions are met, neither the repository checks nor a successful
CI run authorize any protected ASCA route or external CERN operation.
