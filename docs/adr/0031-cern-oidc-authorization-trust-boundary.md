# ADR 0031: Specify the CERN identity and ASCA authorization trust boundary

- **Status:** Proposed for Phase 1A.2.5C1 review
- **Date:** 2026-11-11
- **Scope:** Design and negative-regression contracts only; no runtime authorization
- **Depends on:** ADR 0027, ADR 0028, ADR 0029, ADR 0030

## Context

The single-use native Authorization Code + PKCE diagnostic verifies a CERN ID
Token and observed the application-scoped `asca-developer` claim in one real
operator-initiated transaction. The result is intentionally typed
`UntrustedCernRoleObservation`; `claimed` does not authenticate a user or grant
ASCA access. The current FastAPI composition exposes only read-only foundation
endpoints, and its identity status remains `not_configured`.

A future application login cannot be implemented by treating a diagnostic
return object, a claimed role string, or the current process-local native
attempt store as a production authority. A desktop/public-client native flow
and a browser-accessed web application are different OAuth client/security
architectures. A future web backend-for-frontend (BFF) requires an explicit
registration and review; reusing the native public client is not assumed.

## Decision and provenance classes

1. **Untrusted input:** callback envelopes, token endpoint responses, JOSE
   headers, fetched discovery documents, and user-supplied Python objects.
2. **Locally checked diagnostics:** JWKS/JWS/claims checks and the resulting
   role observation. Even successfully checked, these are non-authoritative
   for the API because the Python composition allows injectable test adapters,
   accepts caller-provided policy inputs and lacks a production session root.
3. **Future authenticated subject:** only a separately designed server-owned
   composition can attest a pinned CERN issuer, verified client registration,
   allowed audience and algorithms, state/nonce/PKCE, one-time callback, trusted
   transport and verification path, with a bound user session. No existing
   result class is promoted to this level by casting or object construction.
4. **Future application authorization:** after establishing an authenticated
   subject, perform a separate fail-closed access decision using the exact
   application-scoped `asca-developer` role and a reviewed MFA/LoA policy.
   Missing-role hints deny; their *absence is not positive MFA/LoA evidence*.
5. **Future delegated resource access:** chATLAS, CERN GitLab and other services
   each require their own audience, scopes, consent and resource permission.
   An ASCA login or ASCA role does not imply delegated access.

## Mandatory gates before enabling any ASCA login

| Gate | Required evidence | Current state |
| --- | --- | --- |
| G1 Client registration | Verified app type, registered redirect URI, authorised scopes and deployment owner; separate native and web registrations | Not attested for web deployment |
| G2 Deployment composition | Server-owned HTTPS BFF/callback path, trusted proxy rules, CSRF protection and secure browser binding | Not implemented |
| G3 Token provenance | Pinned CERN issuer, cryptographic signature, audience/azp, nonce, time validity and code/token binding within trusted server composition | Diagnostic only |
| G4 Replay resistance | Distributed, atomic, one-use transaction store and rotation/cancellation across workers | Process-local diagnostic only |
| G5 Role policy | Exact client-scoped `asca-developer` mapping, strict parsing, positive provenance, fail-closed missing/contradictory claims | Observed, not authorised |
| G6 Assurance | Documented CERN provider semantics for verified MFA and LoA, signed evidence and freshness; absent missing-hints are not proof | Not established |
| G7 Session security | HTTP-only Secure SameSite cookies, CSRF, fixation resistance, short TTL, idle/absolute expiry, logout, key rotation, revocation, audit | Not implemented |
| G8 Resource authorization | Separate per-resource scopes, audiences, endpoint/tool permission checks, least privilege, access revocation | Not implemented |
| G9 Operations | Bounded rate limits, no sensitive logs, audit/alerting, time/clock monitoring and incident procedure | Not established |
| G10 Tests and review | Negative authorization cases, cross-client confusion, invalid assurance, replay, concurrency, secret handling and end-to-end security review | Partial offline coverage only |

**All gates must be evidenced independently** before an authenticated API
route or session is enabled. This is a requirements matrix, not a claim that
the listed protections already exist.

## Prohibited shortcuts

- Do not authorize from `ROLE_STATUS=CLAIMED` or a fabricated
  `UntrustedCernRoleObservation`/`CheckedUntrustedCernOidcToken` object.
- Do not authorize using `cern_roles`, realm roles, email, username or groups
  instead of the selected application's `resource_access` entry.
- Do not infer successful MFA or LoA from empty/absent
  `cern_roles_missing_mfa` or `cern_roles_missing_loa` arrays.
- Do not reuse the native loopback/public client as a web BFF credential or
  create a persistent web session from the native diagnostic.
- Do not treat expired JWTs, stale roles, a revoked CERN user or a successful
  login as proof of continuing ASCA/tool permissions.
- Do not send bearer tokens, refresh tokens, claims or browser-bound secrets to
  LLM prompts, frontend storage, traces, issues, diagnostics or logs.

## This increment

Add this ADR, a requirements/threat-model document and tests asserting the
current negative API boundary. Do not modify production modules, routes,
frontend, dependencies, migrations, or CERN registration. All tests are offline
and must preserve the existing eight quality gates.

## Open decisions for later review

1. What CERN Application Portal registration (and proof of ownership) will
   identify a production web/BFF client distinct from `asca-glibotte-dev`?
2. Which signed, documented CERN claims positively attest required MFA and
   LoA, and how will freshness be checked? Do not assume `amr`/`acr` mappings.
3. What atomic storage, keys, rotation and revocation service can support
   multi-worker sessions and pending transactions?
4. How will independent chATLAS and GitLab authorization be established and
   refreshed without forwarding an ID Token as an access token?
5. What are the explicit allowed routes and tool operations per privilege?

Answers must be supported by operator-approved provider documentation and a
separate implementation ADR. Until then, public identity status must continue
to report authentication disabled.

## References

- ADR 0028: `0028-cern-oidc-role-claims-observation.md`
- ADR 0029: `0029-verified-cern-oidc-role-observation.md`
- ADR 0030: `0030-native-cern-oidc-live-role-observation.md`
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 8252 (native apps): https://www.rfc-editor.org/rfc/rfc8252
- RFC 9700 (OAuth security): https://www.rfc-editor.org/rfc/rfc9700
- RFC 8725 (JWT best practices): https://www.rfc-editor.org/rfc/rfc8725
