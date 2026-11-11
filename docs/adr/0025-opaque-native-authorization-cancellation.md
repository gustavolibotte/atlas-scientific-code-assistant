# ADR 0025: Opaque single-use cancellation capabilities for native authorization attempts

- **Status:** Proposed for Phase 1A.2.4N review
- **Date:** 2026-11-11
- **Scope:** Isolated in-process native OIDC transaction cleanup; no enabled CERN login

## Problem

The Phase 1A.2.4M host revoked pending authorization by calling `reject_callback()` with the privately retained `browser_binding` and `state`. These values were populated during parsing of an `AuthorizationStart` result; if URL validation failed before a valid `state` was retained, a newly saved attempt could remain in memory until its TTL expired. A private cancellation capability must be independent of URL fields and must be consumed atomically by the same store as successful and denied callbacks.

## Decision

1. `PendingAuthorization` and `AuthorizationStart` acquire an optional `cancellation_handle` field (default `None`, excluded from representation) to preserve existing positional callers. A new `OidcAuthorizationService.begin()` issues 32 cryptographically random bytes with `secrets.token_urlsafe`, yielding a 43-character opaque capability that is distinct from the public `state` and private `browser_binding`. It is never included in an authorization URL or a native host public return value.
2. The existing `InMemoryAuthorizationAttemptStore` indexes the SHA-256 digest of each capability separately from its existing browser-binding key. Both indexes and the attempt are guarded by the **same re-entrant lock**. `cancel(handle)` removes the pending attempt and both indexes exactly once. Successful consumption, valid denial, TTL cleanup and explicit cancellation all remove the cancellation index together with the attempt. An incorrect handle cannot cancel another attempt.
3. `OidcAuthorizationService.begin()` cleans up by its generated handle if constructing the authorization URL raises after the attempt has been stored. This path handles ordinary programmatic failures, not arbitrary malicious monkeypatching of a store implementation.
4. `CernOidcNativeCodeExchange.begin()` privately tracks handles created by the underlying service. `cancel_pending()` revokes those handles without a caller-provided binding, HTTP request, authorization URL or `state`; it neither performs a token request nor returns a token. On subsequent begins it reaps references to already-consumed or expired handles to avoid unbounded accumulation.
5. `CernNativeOidcHostTransaction.close()` uses `cancel_pending()` after clearing its protected host state. It no longer relies on retained URL-derived `state` or `browser_binding` to revoke a pending attempt, including on malformed URLs, startup exceptions and repeated closure. The existing lock continues to prevent `close()` from returning before a running code exchange finishes.
6. Keep the previously reviewed PKCE, issuer, callback, one-shot and token-check policies unchanged. This phase modifies only five existing source files, adds two test suites and adds this ADR plus an acceptance checklist.

## Security evidence and limitations

- Cancellation and callback consumption share one lock. Exactly one terminal operation succeeds for a given attempt; cancellation never restores a consumed attempt.
- A fresh authorization URL does not reveal the cancellation handle, including in `repr` of the relevant dataclasses. The capability remains accessible to Python code with direct access to the internal objects; `repr=False` is **not** an OS/process security boundary.
- The existing attempt store remains in-process, not durable, distributed or restart-safe. A random handle is not a bearer token for authentication, a verified CERN identity or membership evidence.
- The host continues to accept only synthetic transport/verifier adapters within its **non-sandboxed** offline test composition. No CERN credentials, real login, browser handoff, FastAPI route or trusted session are introduced.
- The public authorization `state` still needs normal strict callback correlation, even though cancellation no longer depends on it. The host validates URL structure and required parameters, but an upstream adversary with execution privileges in the same Python process can manipulate objects and cannot be defeated by this design.
- General-purpose `OidcAuthorizationService` now expects an `AuthorizationAttemptStore` implementing `cancel()` for rollback if URL construction fails; custom store adapters must implement this method. This is an explicit port contract change, subject to repository-wide type checking.
- A future trusted production integration must use separate registration attestation, durable transaction management, OS listener provenance, proper runtime controls and security review. `cern_sso` remains `not_implemented`.

## References

- ADR 0022: `0022-native-callback-single-use-denial-lifecycle.md`
- ADR 0023: `0023-ephemeral-native-loopback-http-listener.md`
- ADR 0024: `0024-isolated-native-oidc-host-transaction-binding.md`
- RFC 8252: https://www.rfc-editor.org/rfc/rfc8252
- RFC 9700: https://www.rfc-editor.org/rfc/rfc9700
