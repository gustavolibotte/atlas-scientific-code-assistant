# CERN OIDC: authorization threat model and evidence register (Phase 1A.2.5C1)

This document distinguishes **observed evidence** from **required controls**.
It is not a deployment-security attestation and contains no user data or tokens.

## Verified development evidence

- PR #28 added a distinct `--live` native role-observation diagnostic and
  preserved the original non-authoritative native code exchange.
- An authorized operator reported `ROLE_STATUS=CLAIMED` and
  `RESULT=ROLE_OBSERVATION_COMPLETE_NO_SESSION` for development client
  `asca-glibotte-dev`. This proves only that the inspected transaction
  contained the selected role claim after the diagnostic verification path.
- The API exposes the identity status as disabled/unconfigured, with no
  authentication session or delegated chATLAS capability.
- Prior offline tests exercise PKCE, nonce, JWKS/JWS, single-use transactions,
  scoped roles and fail-closed errors. They do **not** establish all deployment
  properties listed below.

## Abuse cases and required mitigations

| Threat | Consequence | Required control before access | Evidence still missing |
| --- | --- | --- | --- |
| Forged `UntrustedCernRoleObservation(status="claimed")` | Unauthorized role elevation | Never accept a DTO as proof; verify from server-owned transaction | Trusted session composition |
| Role from a different client or realm | Cross-client privilege confusion | Match only exact registered client ID and scoped role | Deployed client mapping |
| MFA/LoA omission interpreted as success | Weak assurance admitted | Positive, provider-documented signed evidence and freshness | Verified claim semantics |
| Stolen or replayed authorization callback | Login swapping/replay | Server-held state/binding, PKCE and distributed atomic consume | Multi-worker transaction store |
| Native-loopback result promoted to web login | Unbound browser session | Separate reviewed BFF client, HTTPS, CSRF, secure cookies | BFF registration and route design |
| Session fixation/cookie theft | Account takeover | Rotate session IDs, `HttpOnly`, `Secure`, SameSite, CSRF, timeouts | Session system design |
| Role removed after login | Stale authorization | Short-lived session, refresh/recheck, global revocation and denial | Role revocation design |
| ID Token passed to chATLAS/GitLab | Token/audience confusion | Separate access-token scopes, audience and source policy | Resource-specific permission contract |
| JWT or callback data leaked to logs/LLMs | Secret disclosure | Strict redaction, negative log tests, no credential persistence | Operational log review |
| Compromised reverse proxy/clock/JWKS policy | Invalid token acceptance | Pin trust, proxy boundary and monotonic expiry checks | Production infrastructure review |

## Decisions intentionally deferred

- Whether web login uses a confidential BFF and which separate client ID it
  will use.
- Which CERN assurance claims constitute affirmative MFA and LoA proof.
- Session expiration, logout, refresh, role revalidation, and revocation SLAs.
- Browser cookie and CSRF implementation and multi-instance storage.
- Authorization matrices for ASCA routes, actions and integrations.

## Release gates

**Design review:** resolve the decisions above with documented evidence; keep
identity and resource capabilities disabled until then.

**Implementation review:** add focused negative tests for every newly enabled
authentication route and authorization operation, plus full coverage gates.

**Deployment review:** independent review of TLS, client registration,
session storage, redaction, secrets, logging and emergency revocation.

Current status: **design-only; no production authorization is enabled**.
