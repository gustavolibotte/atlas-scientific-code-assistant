# ADR 0026: Explicit-clock expiry checks for native OIDC cancellation capabilities

- **Status:** Proposed for Phase 1A.2.4O review
- **Date:** 2026-11-11
- **Scope:** In-process, offline-only native OIDC attempt lifecycle
- **Depends on:** ADR 0025

## Context

The Phase 1A.2.4N store enforces expiry on callback consumption and proactively purges expired attempts on insertion. However, cancellation-handle lookup checks only the stored index and cancellation removes an indexed attempt without considering its expiry. A repeated native exchange start can therefore retain a stale handle until a later insertion purges it or a callback triggers expiry.

The store's tests and callers use deterministic simulated timestamps. Direct use of the OS wall clock inside `cancel()` would incorrectly expire valid attempts created under synthetic clocks and introduce a second time authority.

## Decision

1. Extend the concrete `InMemoryAuthorizationAttemptStore.cancel()` and `has_cancel_handle()` operations with an **optional keyword-only `now`** argument. When supplied, it must be a finite integer or float, excluding booleans. Apply the existing `_purge_expired(now)` under the same lock before deciding whether the handle is usable.
2. Expiration uses the pre-existing boundary `attempt.expires_at <= now`. An expired handle is no longer active; the attempt and both indexes are removed before `cancel()` rejects it or `has_cancel_handle()` returns `False`.
3. Leave calls without `now` backward-compatible. In particular, cancellation **without a timestamp** remains a best-effort revocation and cleanup operation even if the attempt is already expired, rather than returning identity or attempting a token exchange. This preserves `OidcAuthorizationService.begin()` rollback and `CernOidcNativeCodeExchange.cancel_pending()` cleanup even if an injected clock fails.
4. During `CernOidcNativeCodeExchange.begin()`, obtain a verified timestamp **before** starting a new attempt. Use that timestamp for the stale cancellation-reference sweep, so invalid clock readings cannot strand a newly stored attempt. The subsequent service `begin()` obtains its own clock reading as before; this is not a monotonic-clock guarantee.
5. Keep existing Python protocol signatures and all public API surfaces unchanged. The optional explicit-clock extensions belong to the concrete in-memory adapter only; no new HTTP routes, permissions, sessions, tokens, or external network access are introduced.
6. Test exact TTL boundaries, invalid times, non-interference between attempts, races among cancellation, expiry lookup and callback consumption, deterministic clocks, and compatibility with all earlier OIDC tests.

## Limitations

- These operations still do **not** perform automatic expiration without activity. An autonomous reaper is not introduced.
- The concrete store remains process-local and is not a durable or multi-worker transaction store.
- A caller that omits `now` does not request a freshness check. This is intentional for rollback and cleanup and must not be used as evidence of a valid authorization.
- A local, synthetic successful `CernOidcNativeCodeExchange` returns a non-authoritative token-check descriptor and never grants CERN identity.
- CERN SSO remains `not_implemented` and the native exchange remains unmounted. Production client registration, permissions, session management and deployment-time security review are separate work.

## References

- ADR 0025: `0025-opaque-native-authorization-cancellation.md`
- RFC 8252: https://www.rfc-editor.org/rfc/rfc8252
- RFC 9700: https://www.rfc-editor.org/rfc/rfc9700
