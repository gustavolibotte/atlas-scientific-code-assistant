# ADR 0022: Correlate native loopback success and denial against one single-use store

- **Status:** Proposed for Phase 1A.2.4K review
- **Date:** 2026-11-11
- **Scope:** Offline, unmounted native-loopback callback lifecycle with single-use OAuth denials

## Context

ADR 0021 validates the untrusted raw HTTP callback envelope without connecting it to an authorization attempt. ADR 0019's `CernOidcNativeCodeExchange` consumes success callbacks atomically and then performs a native token POST, but does not expose a public denial-consumption method. `OidcAuthorizationService.finish(error=...)` consumes a valid denial but always raises, making it unsuitable for distinguishing a successfully consumed denial from invalid state at the caller. The in-process `InMemoryAuthorizationAttemptStore.consume()` already provides the desired atomicity, expiry and constant-time state comparison.

## Decision

1. Add `CernOidcNativeCodeExchange.reject_callback()` as a narrow public denial-consumption operation. It checks nonempty protected binding/state, a bounded safe OAuth error identifier and an optional exact CERN response issuer, then calls **the same** in-process attempt store as the successful code path. It returns `None` only when consumption succeeded. It never makes a token request or returns a grant, nonce or verifier.
2. Add `CernNativeCallbackLifecycle` under infrastructure. Its constructor receives one `CernOidcNativeCodeExchange`, derives and snapshots the native callback registration, and constructs the already reviewed `CernNativeLoopbackCallbackPolicy`. It does not accept a second attempt store, metadata document, verifier or HTTP token transport.
3. `begin()` delegates to the underlying native exchange; the initiating native host must retain its `browser_binding` privately. The `complete(request=..., protected_binding=...)` method first validates the request envelope and the host binding, then forwards a parsed denial to `reject_callback()`, or a parsed authorization code to `exchange_callback()`.
4. A correlated denial returns only an immutable, non-authoritative `NativeCallbackDenied` status. A successful code exchange returns the existing **untrusted** `ExchangedUntrustedCernOidcToken`, not a `VerifiedIdentity`, session, permission or principal. Every expected refusal is sanitized.
5. State mismatch, wrong binding, malformed or wrong-issuer callback must not consume a different pending attempt. Valid success and denial callbacks compete for the same atomic single-use attempt; only one can consume it. A failed token transport/verifier after successful consumption cannot restore an attempt.
6. Use synthetic offline tests for IPv4/IPv6 callbacks, exact issuer, race between denial and success, repeated denial, expiration, wrong state/binding, invalid HTTP input, rejected response, rejection sanitization and absence of token POST on denial.

## Boundaries and deferred work

- **No OS socket or listener:** This dispatcher accepts a forgeable Python request envelope. The future listener must supply actual local/peer socket coordinates from OS APIs, bind only to loopback and shut down after the transaction. It must also enforce time/size/request limits. A local attacker may still connect to the listener; strict syntax alone is not proof of the browser's origin.
- **Protected binding required:** `protected_binding` is an input from the initiating trusted native host, not any query/header/cookie. The calling host must prevent unauthorized access to it. The authorization code and state come from the parsed callback; no caller-supplied code verifier or token is accepted.
- **One process only:** The lock and attempt store do not provide cross-process, distributed or restart-safe replay protection. This phase does not make the flow production-ready.
- **No registration attestation:** `OidcClientRegistration` remains an operator declaration; it is not independently verified with the CERN Application Portal.
- **No login:** Result types are forgeable and non-authoritative, and the lower-level code exchange still accepts test adapters. This increment must not be used as a trusted CERN identity or membership capability. `cern_sso` remains `not_implemented`.
- **Provider compatibility:** The prior strict callback parser intentionally rejects additional Keycloak query parameters; live CERN provider behavior remains unverified. OAuth error identifiers are deliberately not surfaced to callers to avoid leaking text into logs/UI.
- **No token POST on denial:** This is a critical acceptance condition, including concurrent retries and replay after denial. Rate limiting, actual listener shutdown, native application lifecycle integration and operational policies remain future work.

## References

- ADR 0019: `0019-native-oidc-code-to-token-binding.md`
- ADR 0020: `0020-isolated-native-oidc-default-composition.md`
- ADR 0021: `0021-native-loopback-callback-request-policy.md`
- RFC 8252: https://www.rfc-editor.org/rfc/rfc8252
- RFC 9700: https://www.rfc-editor.org/rfc/rfc9700
