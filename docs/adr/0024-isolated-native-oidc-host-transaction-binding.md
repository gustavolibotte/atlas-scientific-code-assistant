# ADR 0024: Isolated native OIDC host transaction binding and cancellation

- **Status:** Proposed for Phase 1A.2.4M review
- **Date:** 2026-11-11
- **Scope:** Unmounted, offline-verified native host transaction; **no production login**

## Context

ADR 0023 owns a real one-shot loopback listener and returns a syntactically accepted raw HTTP envelope; ADR 0022 correlates a parsed callback with an in-process pending authorization using a private `browser_binding`. Until this phase, the host application had to manage the ephemeral redirect URI, protected binding, listener shutdown and cancellation itself. Exposing the binding or allowing external code to invoke `complete()` with a supplied envelope would undermine the purpose of the composed boundary.

## Decision

1. Introduce `CernNativeOidcHostTransaction` in infrastructure with a descriptive `NativeOidcHostStart` and sanitized `OidcNativeHostError` in domain. It constructs the `CernNativeLoopbackListener` **first**, then a `CernOidcNativeCodeExchange` using precisely `listener.registration`, and finally the existing `CernNativeCallbackLifecycle`. The underlying store is limited to one pending attempt per host instance.
2. This *test-only composition* requires explicit provider metadata, synthetic token transport and synthetic verification adapters. It rejects the exact default HTTPS token transport and verification adapter types; however, Python subclasses are forgeable and this is **not a sandbox or enforceable offline guarantee against malicious callers**. The host never itself fetches discovery metadata, opens a browser, contacts CERN or mounts an endpoint. A future production composition must be separate and reviewed.
3. `begin()` may be invoked only once. It validates a canonical pinned authorization endpoint and the exact expected eight authorization query parameters, including the actual ephemeral `redirect_uri` and `code_challenge_method=S256`. It stores the original protected `browser_binding` and public `state` privately and returns only `NativeOidcHostStart(authorization_url, redirect_uri)`. The public result contains **no private binding, verifier, nonce secret or grant**.
4. `complete()` takes no HTTP envelope, state, browser binding, verifier, token or other external parameters. It calls the owned listener's `receive()` (which gets socket coordinates from the OS) and then `CernNativeCallbackLifecycle.complete()` with the private binding. Success returns an existing untrusted, non-authoritative token-check descriptor; a correlated denial returns the existing `NativeCallbackDenied` marker. The listener is closed before the token exchange.
5. The host is a one-shot transaction with a lock around terminal dispatch. Invalid or duplicate starts/completions fail closed; concurrent or late completion cannot create a second token request. `close()` interrupts a blocking receive, removes protected host state and attempts to revoke any remaining pending authorization **using the existing atomic `reject_callback()` path** with the original binding and state. An already consumed attempt is not restored by cancellation.
6. On timeout, unexpected callback, local cancellation, configuration mismatch or failure in an injected adapter, sanitize the host-level exception and close the listener. Cancellation during an already-running token exchange cannot preempt the transport; the lock ensures `close()` cannot return while such a dispatch is still running. No token is persisted or promoted to a session.
7. Add synthetic end-to-end tests with **real loopback sockets** (IPv4/IPv6 where supported), malicious HTTP requests, state and issuer mismatch, denied and successful callbacks, transport/verifier failure, bad provider data, tampered URL, premature close and concurrency. No live CERN calls or real credentials are permitted in tests.

## Explicit exclusions and limitations

- **No production CERN SSO:** No browser handoff, official CERN client registration verification, external identity binding, ATLAS membership attestation, trusted session, permissions, FastAPI route, UI login or live CERN token request. `cern_sso` remains `not_implemented`.
- **Local request forgery:** A malicious local process can connect to the loopback port and send a syntax-valid but uncorrelated callback first, terminating the listener and denying service. The HTTP `202` receipt is **not proof of a successful OAuth transaction**.
- **Process-only guarantees:** The attempt store's atomic consumption is process-local and short-lived. This design has no distributed/restart-safe transaction durability, and no independent attestation of host or socket provenance beyond the OS-provided endpoints.
- **Python object boundaries are not secrets from the same process:** `_browser_binding` is a private Python attribute, not an OS-enforced secret store or process isolation guarantee. Malicious Python code in the same process can inspect or mutate it.
- **Revocation limits:** If a forged upstream `begin()` object supplies an invalid URL or no valid state, the host may be unable to revoke a newly created underlying attempt. The binding is never exported and the in-memory attempt expires by TTL. A future production store needs explicit cancellation by opaque attempt handle.
- **Listener lifetime:** A listener that has not entered `receive()` has no autonomous timeout. Always manage the host using a context manager or call `close()` explicitly; the overall receive deadline starts when `complete()` invokes `receive()`.
- **Socket and transport cancellation:** The host can close its listener while waiting, but cannot interrupt a synthetic/verifier transport once invoked. Real HTTPS transport timeouts and an operational lifecycle require separate engineering.
- **Provider compatibility:** Exact callback query restrictions and ephemeral redirect registration must be tested against actual CERN provider behaviour and approved through the CERN Application Portal before any enabled-login decision.

## References

- ADR 0019: `0019-native-oidc-code-to-token-binding.md`
- ADR 0021: `0021-native-loopback-callback-request-policy.md`
- ADR 0022: `0022-native-callback-single-use-denial-lifecycle.md`
- ADR 0023: `0023-ephemeral-native-loopback-http-listener.md`
- RFC 8252: https://www.rfc-editor.org/rfc/rfc8252
- RFC 9700: https://www.rfc-editor.org/rfc/rfc9700
