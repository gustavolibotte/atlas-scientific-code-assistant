# Phase 1A.2.4O acceptance: expiry-aware native cancellation handle lifecycle

## Scope

Enhance the isolated, in-process native OIDC attempt store with explicit-clock expiry checks and bounded handle cleanup. Preserve all existing tests, API routes, dependencies, and authorization boundaries. This is **not** CERN SSO enablement.

## Acceptance checklist

- [ ] Start from clean `main` commit `aaf944438f40f8bfb44b5c74b4597f5bf3e2913c`; create branch `feat/oidc-native-ttl-lifecycle-1a2-4o`.
- [ ] Apply the guarded candidate only after a successful `--dry-run`; check all two existing file Git blob hashes.
- [ ] Exactly two existing production modules modified (`identity_memory.py`, `oidc_native_exchange.py`) and four files added (two test suites, ADR 0026, this checklist).
- [ ] `cancel(handle, now=...)` rejects and removes expired attempts at the exact TTL boundary; `has_cancel_handle(handle, now=...)` returns `False` and removes expired indexes.
- [ ] Reject malformed explicit timestamps without mutating the store. The legacy timestamp-free cleanup path remains compatible.
- [ ] Preserve cancellation/callback single-use and in-process atomicity under concurrent interleavings; never cancel unrelated live attempts.
- [ ] In native `begin()`, check the timestamp before creating a new attempt and use the same verified timestamp for stale handle lookup.
- [ ] No claims of clock-monotonicity, token authority, trusted user identity or CERN permissions.
- [ ] Run targeted tests and official Mac diagnostic suite; require `PASS=8 FAIL=0 SKIPPED=0`, no Ruff/mypy failures and no new unreviewed warnings.
- [ ] Review complete diff, full test counts and coverage, and exact six-path scope before authorizing commit and pull request.
- [ ] Verify all 13 GitHub CI jobs on the PR before merge; rerun all 13 after merge and the eight local gates before formally closing the phase.

## Focused verification

```bash
uv run --locked ruff check src tests scripts
uv run --locked ruff format --check src tests scripts
uv run --locked mypy src
uv run --locked pytest -q tests/unit/test_oidc_ttl_lifecycle.py tests/security/test_oidc_ttl_lifecycle_security.py
uv run --locked pytest -q tests/unit/test_oidc_cancel_handle.py tests/security/test_oidc_cancel_handle_security.py tests/unit/test_oidc_native_exchange.py tests/security/test_oidc_native_exchange_security.py tests/unit/test_oidc_native_host.py tests/security/test_oidc_native_host_security.py
uv run --locked python scripts/run_checks.py

git diff --check
git diff --stat
git status --short
```

## Security and release gate

Do not commit, push, or merge this candidate before local diagnostics are shared and reviewed. No live CERN requests, credentials, browser sign-in, production routes, or permissions are permitted in this phase.
