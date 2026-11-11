# ADR 0023: Isolated ephemeral native loopback listener and terminal socket shutdown

- **Status:** Proposed for Phase 1A.2.4L review
- **Date:** 2026-11-11
- **Scope:** Unmounted, offline, one-shot native HTTP listener for syntactically valid OIDC loopback callbacks; not authentication

## Context

ADR 0021 defines the untrusted callback HTTP parser, and ADR 0022 uses a protected native binding and atomic in-process attempt store to consume success and denial. Neither starts an OS listener. A real listener must not trust HTTP headers for peer/local socket addresses, bind to a wildcard interface, choose a stale fixed port, leak callback values in HTTP responses or remain open indefinitely.

RFC 8252 recommends native clients bind an ephemeral loopback port, use the bound port in the redirect URI, and close the listener when the response arrives. RFC 9700 additionally requires strict callback and state/PKCE correlation, which remains in the previously reviewed lifecycle.

## Decision

1. Introduce `CernNativeLoopbackListener` only under infrastructure, plus descriptive non-authoritative `NativeLoopbackListenerBinding` and sanitized `OidcNativeListenerError` domain declarations. No API routes, FastAPI mounts, frontend, OAuth identity results or dependencies change.
2. The constructor accepts only the literal IPv4 `127.0.0.1` or IPv6 `::1`; it creates an OS TCP socket and binds `(host, 0)`, allowing the kernel to select the port. IPv6 sockets explicitly set `IPV6_V6ONLY`. No wildcard addresses, DNS resolution, proxies, port reuse or externally selected port are accepted.
3. Construct an `OidcClientRegistration` using the **actual bound port**; this remains an unverified operator declaration. Its exact redirect URI and callback policy must be used by any subsequent `CernNativeCallbackLifecycle`/native code exchange. Confirm CERN registration and allowed ephemeral port behavior independently before enabling any login.
4. Read raw HTTP/1.1 request lines and duplicate-preserving headers from the accepted TCP socket, using actual `getpeername()` and `getsockname()` values. Pass the envelope to the ADR 0021 policy with **no** normalization of duplicate header fields or acceptance of forwarded socket attributes.
5. Enforce a total monotonic receive deadline, per-connection deadline, maximum number of accepted connections, maximum request-header bytes, a single active consumer, and bounded header count. Malformed connections are rejected with a fixed generic response, without consuming any authorization attempt. Resource exhaustion, closing the context, and explicit cancellation close the listener.
6. A **syntactically accepted** callback receives an HTTP `202 Accepted` response with no body and no-store headers. This is strictly a transport receipt, **not** proof of a matching `state` or successful login. The socket is closed before the caller processes the returned `NativeLoopbackHttpRequest` with `CernNativeCallbackLifecycle.complete(request=..., protected_binding=...)`. Both OAuth success and denial follow the same shutdown policy.
7. Repeated `receive()` calls and concurrent receivers fail closed. Every execution path that exits `receive()` closes the listening socket; use of the class as a context manager additionally closes sockets if the caller never starts receiving.
8. Add real local-loopback IPv4/IPv6 integration tests, adversarial request tests, resource-limit tests and independent synthetic socket-failure tests. All tests remain offline: **no CERN service or live credentials**.

## Known limitations and deferred requirements

- **Not a production login:** No browser opening, CERN registration attestation, trusted identity, permission, group membership, web BFF, distributed attempt store, production sessions or ASCA API route is introduced. `cern_sso` remains `not_implemented`.
- **Native host must orchestrate:** This listener returns a forgeable Python envelope after transport shutdown; it does not call `CernNativeCallbackLifecycle.complete()`. The native host must keep the original `browser_binding` protected and complete the state/PKCE transaction separately; do not obtain binding from the HTTP callback.
- **Local adversaries:** A malicious local process may connect first, supply a syntactically valid but uncorrelated callback, and trigger terminal socket closure (denial of service). Neither `Host`, peer loopback IP nor the HTTP `202` authenticates the sender. The state/nonce/PKCE checks protect against unauthorized acceptance of the request, not all local denial-of-service attacks.
- **Response size and timing:** `202` acknowledges syntax before OIDC processing. An oversized sender may observe a TCP reset rather than HTTP `400` when unread bytes remain, which is still a refusal. Browser-facing UX and explicit outcome acknowledgment remain future work.
- **Lifetime if never started:** The total deadline starts when `receive()` is invoked. Hosts must always use the context manager or call `close()` if they do not call `receive()`. The implementation has no background worker or automatic timer for unused sockets.
- **Resource limits:** A per-connection read deadline, total deadline and connection-count budget bound the receive operation; other processes can still exert OS-level pressure. No claim is made about process-level hardening or anti-interception guarantees.
- **Provider compatibility:** The pre-existing strict callback policy may reject provider-specific extension fields, and this has not been checked against live CERN responses.

## References

- ADR 0021: `0021-native-loopback-callback-request-policy.md`
- ADR 0022: `0022-native-callback-single-use-denial-lifecycle.md`
- RFC 8252: https://www.rfc-editor.org/rfc/rfc8252
- RFC 9700: https://www.rfc-editor.org/rfc/rfc9700
