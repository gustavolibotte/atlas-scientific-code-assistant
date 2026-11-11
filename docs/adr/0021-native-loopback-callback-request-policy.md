# ADR 0021: Offline native-loopback OIDC callback request validation

- **Status:** Proposed for Phase 1A.2.4J review
- **Date:** 2026-11-11
- **Scope:** Strict, unmounted HTTP request parsing policy for a future native-loopback listener; no authentication

## Context

The isolated CERN native client bootstrap in ADR 0020 builds the existing Authorization Code + PKCE/token-validation chain with default adapters, but there is no native HTTP listener. The native exchange accepts a caller-provided local binding, state and authorization code, assuming a future host supplies these from a protected callback context. RFC 8252 permits loopback redirects with an IP literal and an ephemeral bound port; it recommends binding only to loopback and closing the listener after the authorization response. RFC 9700 requires state/PKCE CSRF protection and strict redirect matching. An HTTP `Host` header, source loopback address or syntactically valid `state` is **not** proof of genuine browser origin or CERN authorization.

## Decision

1. Introduce `NativeLoopbackHttpRequest` and `ParsedUntrustedNativeCallback` as repr-hidden, forgeable domain declarations. Add `CernNativeLoopbackCallbackPolicy` in infrastructure. Neither module opens a socket, mounts an API endpoint or consumes an authorization attempt.
2. Accept a reconstructed `OidcClientRegistration` in `NATIVE_LOOPBACK` mode only. Restrict this first policy to exact `http://127.0.0.1:{port}/{path}` or `http://[::1]:{port}/{path}` literals. The registered callback path and port are immutable within the policy. This is intentionally narrower than some locally valid loopback IP registrations.
3. Require an HTTP/1.1 `GET` with an origin-form request target containing exactly the registered path and one query, a single matching `Host` header, no body, and no transfer encoding, proxy-forwarding, cookies, Authorization headers or untrusted Origin header. Reject ambiguous header structures and invalid control bytes.
4. Require the future listener to populate `local_ip`, `local_port` and `peer_ip` **from the real socket**, never from HTTP/query headers. This policy validates their literal shapes and equality with the configured loopback listener, but cannot independently attest where those values came from.
5. Allow only `state`, exactly one of `code` / `error`, and optionally `iss`. Enforce bounded query length and parameter count, unambiguous percent-decoding, no duplicates, strict nonce-shaped `state`, visible-ASCII code and a safely bounded error identifier. When present, `iss` must match the exact CERN issuer. Do not use any response parameter as a URL or redirect target.
6. Return only a parsed, **untrusted** callback without the browser binding, authorization grant, identity, role, session, token or access permissions. The browser/native binding MUST come from protected local host state and MUST be checked with `OidcAuthorizationService` / the atomic single-use attempt store before any token exchange. Parsing alone is repeatable and does not confer replay protection.
7. Represent OAuth error callbacks as `error`, never as a code or success. A future listener must correlate and consume the pending attempt on a denial and close the listener; this phase deliberately does not connect denial handling to an attempt store.
8. Run synthetic offline positive and adversarial tests for host confusion, method/request-target smuggling, duplicate and malicious headers, percent-encoding ambiguity, state tampering, wrong issuer, source/bind address mismatch and forged input contracts.

## Restrictions and follow-up

- **No actual listener or source attestation:** A caller can fabricate the Python envelope. The future listener must securely bind an actual OS socket to the selected loopback address and port, provide the real socket addresses, limit request count/size and close after a transaction. These guards are necessary but not sufficient to stop a malicious local process.
- **Provider compatibility not validated:** The policy intentionally rejects query extension parameters such as `session_state`, `error_description` and `error_uri`. Check actual permitted CERN responses before any production deployment and add only narrowly approved extensions with regression tests.
- **HTTP/1.1 only, exact host and IP literal:** An eventual real listener must ensure it preserves the original request-target and duplicate HTTP headers for validation. A framework that normalizes or discards duplicate headers is not sufficient for this contract without additional controls.
- **No login or shared state:** The existing in-memory store is process-local. No browser session, confidential BFF token exchange, user principal, role/group/ATLAS membership or CERN login is introduced. The `cern_sso` API capability remains `not_implemented`.

## References

- ADR 0019: `0019-native-oidc-code-to-token-binding.md`
- ADR 0020: `0020-isolated-native-oidc-default-composition.md`
- RFC 8252, OAuth 2.0 for Native Apps: https://www.rfc-editor.org/rfc/rfc8252
- RFC 9700, OAuth 2.0 Security Best Current Practice: https://www.rfc-editor.org/rfc/rfc9700
