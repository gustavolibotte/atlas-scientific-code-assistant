# Phase 1A.2.4K acceptance: native callback lifecycle and single-use denial

## Scope

Connect the existing strict native HTTP callback parser to the same authorization-attempt store used by native success exchange. Valid OAuth denials must atomically consume their pending attempt without performing any token request. Keep all code unmounted and non-authenticating; do not introduce sockets, session endpoints, dependencies or frontend changes.

## Checklist

- [ ] Begin from clean `main` at PR #19 merge commit `fd7de67dfa30e386660f03c17af1426892ac0a74`, after 13/13 remote CI and 8/8 local gates.
- [ ] Create `feat/oidc-native-single-use-denial-1a2-4k`, add six domain/infrastructure/test/doc files and narrowly edit `src/asca/infrastructure/oidc_native_exchange.py` (seven paths total).
- [ ] No changes to existing API routes, frontend, `pyproject.toml`, `uv.lock`, the native callback parser or its old tests.
- [ ] Require a strictly validated `NativeLoopbackHttpRequest` and protected host-origin binding; never take a binding, verifier or identity from the HTTP callback.
- [ ] Denial success must return a non-authenticating marker only, without token exchange or verifier invocation.
- [ ] Consume denial and success against the SAME atomic attempt store, preventing denial/denial and denial/success replay in-process.
- [ ] Invalid state, binding, issuer or HTTP input must fail without consuming the legitimate attempt; expired attempts must be rejected.
- [ ] Test simultaneous callbacks, concurrency, transport errors, type-forged requests, issuer mismatch and sanitized exceptions with entirely synthetic data.
- [ ] Run Ruff, formatting, mypy, both focused pytest entry points and `scripts/run_checks.py`; require `PASS=8 FAIL=0 SKIPPED=0` and inspect diagnostics/coverage before commit.
- [ ] Inspect `git diff --check`, exact seven-path diff and zero dependency changes; require code review and 13/13 CI before merge, then 13/13 and local 8/8 after merge to close.

## Validation commands

```bash
uv run --locked ruff check --select I --fix src/asca/domain/oidc_native_lifecycle.py src/asca/infrastructure/oidc_native_lifecycle.py src/asca/infrastructure/oidc_native_exchange.py tests/unit/test_oidc_native_lifecycle.py tests/security/test_oidc_native_lifecycle_security.py
uv run --locked ruff format src/asca/domain/oidc_native_lifecycle.py src/asca/infrastructure/oidc_native_lifecycle.py src/asca/infrastructure/oidc_native_exchange.py tests/unit/test_oidc_native_lifecycle.py tests/security/test_oidc_native_lifecycle_security.py
uv run --locked ruff check src tests scripts
uv run --locked pytest -q tests/unit/test_oidc_native_lifecycle.py tests/security/test_oidc_native_lifecycle_security.py
uv run --locked python -m pytest -q tests/unit/test_oidc_native_lifecycle.py tests/security/test_oidc_native_lifecycle_security.py
uv run --locked python scripts/run_checks.py
git diff --check
git diff --stat
git status --short
```

## Test evidence and limitations

An isolated Linux/Python 3.13 reconstruction of the available OIDC unit and security tests passed **1,663 tests**, including **81 new lifecycle tests**, with 100% statement and branch coverage of the two added modules. The isolated fixture is not the complete repository and does not run the full Mac quality gate or frontend. The official Mac execution, diagnostics ZIP and GitHub Actions remain mandatory before acceptance.

**Not a production CERN login:** The implementation has no live listener, no verified CERN client registration, no durable attempt store, no trusted identity/session authorization boundary and no production authentication routes. CERN SSO stays disabled.
