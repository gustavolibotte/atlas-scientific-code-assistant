# Phase 1A.2.4N acceptance: opaque native attempt cancellation and lifecycle hardening

## Scope

Remove authorization URL state from cancellation dependencies. Keep the native host and all CERN SSO functionality disabled and unmounted. Use only synthetic tests with local loopback traffic; do not contact CERN or supply actual credentials.

## Acceptance checklist

- [ ] Start from `main` commit `d77cfca9e624c79e362f34c6dc064410f065f83e`; install on branch `feat/oidc-native-cancel-handle-1a2-4n`.
- [ ] Exactly five existing source files modified: `domain/identity.py`, `application/identity.py`, `infrastructure/identity_memory.py`, `infrastructure/oidc_native_exchange.py`, `infrastructure/oidc_native_host.py`; exactly four new files (two tests and two documents). No API, frontend, requirements or lockfile changes.
- [ ] Generate a separate 256-bit opaque cancellation capability at each authorization start; never expose it in the authorization URL, host public start result or dataclass representation.
- [ ] Keep digest-indexed cancellation handles and pending attempts synchronized under the store lock. Consume/cancel/expiry remove both indexes. Wrong, duplicate, stale or cross-attempt handles fail without cancelling any other attempt.
- [ ] Failure during URL construction revokes the newly stored attempt.
- [ ] A host's malformed or missing `state` on a returned authorization URL still triggers cancellation of the underlying attempt, without needing the URL-derived state.
- [ ] Exercise concurrency between callback consumption and cancellation, cancellation during blocked receive and during an in-flight synthetic token exchange, repeated close and repeated begin cycles without retained stale handles.
- [ ] Confirm backwards compatibility of existing authorization dataclass positional construction and existing OIDC tests. Custom implementations of `AuthorizationAttemptStore` must satisfy the new `cancel` contract.
- [ ] Run Ruff, Ruff formatting, mypy, focused pytest and full official `scripts/run_checks.py` on Mac. Require `PASS=8 FAIL=0 SKIPPED=0` before commit.
- [ ] Check exactly nine affected paths, `git diff --check`, no dependencies, no new routes, and inspect the coverage and diagnostics ZIP.
- [ ] Review 13/13 PR CI **before** merge, then review 13/13 post-merge CI and 8/8 local Mac gates to close the phase.

## Focused verification

```bash
uv run --locked ruff check --select I --fix src/asca/domain/identity.py src/asca/application/identity.py src/asca/infrastructure/identity_memory.py src/asca/infrastructure/oidc_native_exchange.py src/asca/infrastructure/oidc_native_host.py tests/unit/test_oidc_cancel_handle.py tests/security/test_oidc_cancel_handle_security.py
uv run --locked ruff format src/asca/domain/identity.py src/asca/application/identity.py src/asca/infrastructure/identity_memory.py src/asca/infrastructure/oidc_native_exchange.py src/asca/infrastructure/oidc_native_host.py tests/unit/test_oidc_cancel_handle.py tests/security/test_oidc_cancel_handle_security.py
uv run --locked ruff check src tests scripts
uv run --locked pytest -q tests/unit/test_oidc_cancel_handle.py tests/security/test_oidc_cancel_handle_security.py
uv run --locked python -m pytest -q tests/unit/test_oidc_cancel_handle.py tests/security/test_oidc_cancel_handle_security.py
uv run --locked python scripts/run_checks.py

git diff --check
git diff --stat
git status --short
```

## Validation notes

The reconstructed offline environment contains the previous native host and OIDC modules but not the complete ASCA repository and frontend. Its earlier host regression plus the new cancellation tests are a useful partial check **only**. Full Mac type/lint/frontend checks and the published GitHub Actions matrix are required. The local runtime may use a different Python version from the Mac.
