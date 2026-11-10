# Phase 1A.2.4H acceptance: isolated native code-to-token binding

## Scope

Bind a locally consumed native-loopback authorization code and the corresponding stored PKCE verifier to the actual POST performed by the existing native CERN OIDC token HTTP adapter. Strictly parse the returned response and validate its ID token under the existing untrusted-result JWKS/JWS/claims pipeline. Do not modify the BFF binder, add confidential client authentication, enable CERN login, create principals/sessions or add dependencies.

## Acceptance checklist

- [ ] Start from clean `main` at PR #16 merge `3594151`, after 13/13 post-merge CI and local 8/8 quality gates.
- [ ] Work in `feat/oidc-native-code-to-token-binding-1a2-4h`, adding exactly six new files; leave existing code, `pyproject.toml` and `uv.lock` unchanged.
- [ ] Permit `NATIVE_LOOPBACK` registrations only; reject `WEB_BFF` and forged/unreviewed client or provider metadata.
- [ ] Create/store the authorization attempt internally; produce nonce, state, local binding and S256 PKCE verifier without exposing an authenticated principal.
- [ ] Atomically consume the original local binding and returned `state`; reject wrong binding, state, replay and expired attempts.
- [ ] Build the outgoing token POST from the consumed `AuthorizationCodeGrant` using the approved existing builder, never from caller-supplied token data. Require original code, exact registered redirect/client ID, stored verifier and consumed nonce.
- [ ] Use the existing native HTTPS POST transport, enforce pinned endpoint and no redirects, then parse its response under the existing token-response parser.
- [ ] Call existing JWS/claims verification with the internally derived client ID and nonce. Never create identity, session, role, access-token store or membership claims.
- [ ] Reject malformed callbacks before consumption; failures during POST, response parsing or verification after consumption must never restore the attempt.
- [ ] Exercise concurrent replay, token HTTP errors, malformed responses, invalid metadata, tampering and forged intermediate data using offline synthetic test fixtures.
- [ ] Exercise actual cryptographic verification under ephemeral RS256, PS256 and ES256 signing keys with fake HTTP responses, without live CERN requests.
- [ ] Run focused tests, Ruff, mypy, full frontend tests/build and `uv run --locked python scripts/run_checks.py`; require PASS=8 FAIL=0 SKIPPED=0.
- [ ] Inspect diagnostics ZIP, coverage, `git diff --check`, status, exactly six added files and absence of dependency changes before committing.
- [ ] Review remote diff and require 13/13 GitHub Actions on PR and 13/13 after merge before formal closure.

## Local commands

```bash
uv run --locked ruff check --select I --fix src/asca/domain/oidc_native_exchange.py src/asca/infrastructure/oidc_native_exchange.py tests/unit/test_oidc_native_exchange.py tests/security/test_oidc_native_exchange_security.py
uv run --locked ruff format src/asca/domain/oidc_native_exchange.py src/asca/infrastructure/oidc_native_exchange.py tests/unit/test_oidc_native_exchange.py tests/security/test_oidc_native_exchange_security.py
uv run --locked ruff check src tests scripts
uv run --locked pytest -q tests/unit/test_oidc_native_exchange.py tests/security/test_oidc_native_exchange_security.py
uv run --locked python scripts/run_checks.py
git diff --check
git diff --stat
git status --short
```

## Security notice

All tests must use synthetic keys, codes, IDs and tokens. Do not use live CERN accounts, CERN network calls, client secrets, production cookies or `.env` files in tests or diagnostics. A successful test of this isolated native composition does not enable the web BFF or establish a trusted CERN identity.
