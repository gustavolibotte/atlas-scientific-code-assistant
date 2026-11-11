# ADR 0027: Opt-in CERN native OIDC code-exchange diagnostic

- **Status:** Proposed for Phase 1A.2.5A review
- **Date:** 2026-11-11
- **Scope:** One-shot local CLI; no API login or authenticated ASCA session
- **Depends on:** ADRs 0017, 0019, 0020, 0021-0026

## Context

The ASCA CERN application `asca-glibotte-dev` is officially registered as a public OIDC client with redirect `http://127.0.0.1/oidc/callback`. An independent real-browser probe demonstrated that the CERN authorization server sends a code to `http://127.0.0.1:<ephemeral-port>/oidc/callback`, using Authorization Code and PKCE S256. That probe intentionally discarded the code.

Existing ASCA components already implement ephemeral loopback listening, single-use callback correlation, code/PKCE exchange, pinned CERN metadata discovery, JWKS signature verification and OIDC claims checks. The current native host accepts explicit test transport/verifier adapters and cannot be promoted to a production login root. The default-only bootstrap separately constructs a native exchange from constrained HTTPS adapters.

## Decision

1. Introduce an **explicitly opt-in CLI diagnostic** with `--live`; default execution makes no network request and does not open a browser.
2. Open the OS-selected IPv4 loopback listener **before** obtaining default-only discovery/exchange composition, binding the registered public client ID `asca-glibotte-dev` and path `/oidc/callback` to the socket.
3. Reuse `CernOidcNativeUntrustedBootstrap` for pinned public discovery and default HTTPS/JWKS adapters, and `CernNativeCallbackLifecycle` for private binding, strict callback parsing, and single-use exchange.
4. Keep `browser_binding`, authorization URL, callback URL/query, authorization code, PKCE verifier, signed ID token, access token, signing key IDs, and token claims out of CLI diagnostics. The only output is a fixed set of non-sensitive status labels.
5. Revoke pending authorization capabilities on every terminal path. Listener and token-bearing objects remain in process only; no cache, session, identity, token storage, API mount or external provider application is created.
6. The success status `ID_TOKEN_CHECK_PASSED_NO_SESSION` is **not** a verified ASCA principal or authorization grant. The existing result DTOs are forgeable; role membership `asca-developer` is **not checked** in this increment.
7. Keep production modules unchanged except for the narrowly scoped Keycloak `session_state` callback compatibility correction described below. The new diagnostic does not add network access to `create_app()` or provide untrusted input ports for transport, issuer, JWKS URL, client secret, or tokens.
8. Restrict live testing to an explicitly authorized account using the registered development client; all automated tests remain offline and use synthetic collaborators.

## Limitations and follow-up

- No `asca-developer` role enforcement, MFA/LoA attestation, session creation, chATLAS access, logout, or token persistence. The next security increment must examine signed, verified roles **in the validated token pipeline**, not in a forged caller-supplied DTO.
- The complete callback transport can still be denied by local-process interference. Strict state and PKCE minimize code-injection risk but do not authenticate the local process.
- This diagnostic uses the synchronous, process-local in-memory authorization store and makes no multi-worker or monotonic-clock guarantees.
- CERN may require adjustments to token-claim policy or token response formats. Any failure is recorded with a sanitized outcome and investigated through separately controlled diagnostics, never by printing raw tokens.
- A genuinely authenticated session will require a reviewed trust root, lifecycle, role handling, revocation, and controlled storage; none is enabled here.

## References

- CERN Authentication and Authorization Service, *OIDC configuration and usage* (operator-provided document, 2026-11-11).
- RFC 8252, OAuth 2.0 for Native Apps.
- RFC 9700, Best Current Practice for OAuth 2.0 Security.

## Verified CERN callback extension (Phase 1A.2.5A correction)

The operator's independent, no-token-exchange CERN callback-shape probe observed
`state`, `code`, `iss` and `session_state`. The previously strict parser allowed
at most three parameters and rejected `session_state`. The ASCA live probe was
therefore rejected before its callback-received milestone; this is a supported
root-cause hypothesis for that failure, subject to re-running the real flow.

Allow at most four distinct query parameters: the existing `state`, `code` or
`error`, `iss`, plus optional `session_state`. Reject duplicate and unknown
parameters as before. Validate `session_state` as a bounded ASCII unreserved
opaque value, then discard it. Do not add it to any callback result, security
binding, token request, identity record, role check or session. State, PKCE,
issuer, socket and single-use protections remain unchanged. Add offline positive
and adversarial regression tests and re-run the entire quality-gate suite.

## CERN token-endpoint ID Token `at_hash` compatibility correction

The operator's real CERN diagnostic reached the token endpoint, parsed its
response, fetched the official JWKS and verified the JWS signature. A
privacy-preserving claims-shape probe showed `at_hash` present, `c_hash` and
`s_hash` absent, and a rejection at the pre-existing unbound-hashes rule.

OpenID Connect Core 1.0 Section 3.1.3.8 permits the optional `at_hash` in an
ID Token returned from the Authorization Code token endpoint. For the approved
RS256, PS256 and ES256 algorithms, bind it to the **access_token from the same
parsed token response**: SHA-256 of the ASCII token, leftmost 128 bits,
base64url without padding, and constant-time comparison. Invalid, missing,
malformed or mismatched hashes fail closed. Direct claims checks lacking token
context continue to reject `at_hash`; `c_hash` and `s_hash` remain unsupported.

Do not echo or retain the access token or hash. The resulting output is still a
forgeable non-authenticating check, never a CERN principal, role decision,
application session or chATLAS capability. Any further live mismatch must be
diagnosed separately. See https://openid.net/specs/openid-connect-core-1_0.html .
