# ADR 0033: Keep CERN web-operator evidence intake separate from authorization

- **Status:** Proposed for Phase 1A.2.5C3 review
- **Date:** 2026-11-12
- **Depends on:** ADR 0031, ADR 0032 and the C2 evidence register
- **Scope:** Offline intake contract, documentation and regression tests only
- **Decision authority:** Future application owner and independent security reviewer

## Context

Phase 1A.2.5B3 observed the `asca-developer` application role in one authorized
native/public-client CERN OIDC diagnostic. C1 defined ten mandatory security
gates (G1–G10). C2 reviewed CERN documentation and recorded unresolved evidence
for G1 (web registration), G6 (MFA/LoA assurance) and G7 (session lifecycle).
No separate ASCA web client, positive assurance contract or production session
has been attested. The native result `ROLE_STATUS=CLAIMED` is not authorization.

C3 must allow the operator to catalogue whether non-secret evidence is awaiting
review, without pretending that a self-authored JSON declaration attests CERN
settings, authorizes an identity or proves a session design is operational.

## Decision

1. Add a minimal versioned **operator intake template** for G1, G6 and G7.
   Only `not_supplied` or `submitted_for_review` is representable. No
   `approved`, `ready`, `authorized`, or `verified` state exists.
2. An optional, *local* CLI may validate the template or a separately held
   candidate record. The validator is offline, refuses duplicate JSON keys,
   unknown fields, unbounded data, symlinks and malformed references.
3. A `submitted_for_review` gate requires an opaque, non-secret `EVIDENCE-1234`
   style tracking reference. It is **not** a URL, CERN client ID, screenshot,
   credential, approval or attestation. The validator does not dereference it.
4. The default template remains entirely `not_supplied`. Do not commit filled
   operator records, provider screenshots or organizational membership data.
   Real evidence belongs in an access-controlled review workflow with independent
   verification by the application owner/security reviewer.
5. The validator prints only fixed non-sensitive fields and always returns
   `OPERATOR_REVIEW_REQUIRED` for a structurally valid record, regardless of
   whether any gate was marked `submitted_for_review`. Exit status zero means
   **syntax only**, never login or deployment readiness.
6. The current identity API remains `not_configured`. No web login, callback,
   session, permission, secrets, data storage, token refresh or chATLAS support
   is introduced. No live CERN network operations are performed.
7. Extend offline security tests to reject forged states and secret-bearing
   records, and to ensure submitted evidence is not silently promoted to trust.

## Gate-specific evidence to collect later (outside the repository)

| Gate | Required non-secret operator-reviewed evidence | Still unresolved |
| --- | --- | --- |
| G1 | Separate web/BFF application owner, registered client type, exact HTTPS redirect, grant and authentication methods, approved scopes, controlled deployment | Web registration and deployment attestation |
| G6 | CERN-authored assurance contract establishing **positive** role/MFA/LoA guarantee or documented signed evidence, freshness and downgrade behavior | No approved `amr`/`acr` mapping or equivalently trusted policy |
| G7 | Reviewed distributed transaction/session store, cookie and CSRF policy, approved idle/absolute TTL, rotation, logout, revocation, secrets and emergency invalidation ownership | No session policy or implementation |

An absent `cern_roles_missing_mfa` or `cern_roles_missing_loa` indicator is
**not affirmative proof**. An observed `resource_access[client_id].roles`
entry is **not a durable permission grant**. An ID Token for ASCA is **not** a
delegated access token for chATLAS or GitLab.

## Trust boundary

```text
CERN published documentation / native diagnostic
    -> non-authoritative architectural context only

Operator-submitted opaque evidence reference
    -> syntactically checked local intake record
    -> independent evidence verification still required

Future reviewed server-owned OIDC web composition
    -> authenticated identity (not implemented)
    -> separate assurance + role decision (not implemented)
    -> controlled server-side session (not implemented)
    -> independent resource permissions (not implemented)
```

No arrow from an intake record to an authenticated identity or permission is
permitted. The CLI uses no network, cannot verify the CERN Applications Portal,
and intentionally does not offer an approval or readiness result.

## Non-secret handling

- Never paste or commit client secrets, ID/access/refresh tokens, callback
  parameters, JWT claims, user account details, cookies or unredacted screenshots.
- Store provider screenshots and actual configuration records only in an
  appropriate restricted system; do not add them to CI artifacts or prompts.
- Only a separately approved, non-sensitive evidence tracking reference may
  appear in a local intake record. The validator never prints this reference.
- Do not infer official registration from example application documentation.
- Do not infer freshness, successful MFA or LoA merely because the role was
  observed in one native diagnostic.

## Deferred decisions and stop condition

C3 does **not** answer the open operator questions from ADR 0032. The owner must
first supply verifiable non-secret evidence in an access-controlled workflow,
and an independent reviewer must agree on provider semantics and architecture.
The corresponding G1/G6/G7 and dependent G2–G5/G8–G10 gates remain blocked.

**STOP:** no authenticated ASCA route/session or chATLAS access may be enabled
based on this document, a CLI exit code, or a populated intake record.

## References

- ADR 0031: `0031-cern-oidc-authorization-trust-boundary.md`
- ADR 0032: `0032-cern-web-client-assurance-session-review.md`
- C2 register: `docs/security/cern-web-oidc-evidence-register.json`
- CERN OIDC documentation provenance is recorded in the C2 evidence register.
- OAuth 2.0 Security Best Current Practice: https://www.rfc-editor.org/rfc/rfc9700
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
