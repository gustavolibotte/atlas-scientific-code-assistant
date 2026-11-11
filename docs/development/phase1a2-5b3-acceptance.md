# Phase 1A.2.5B3 acceptance: native CERN role-claim diagnostic

The objective is to connect a fixed, non-authoritative CERN role observation to
**the same consumed** native OAuth authorization-code transaction. No ASCA
login/session/permission or chATLAS access is implemented.

## Acceptance checklist

- [ ] Clean `main` at `60418cf56313720553f34331263393df0e0aa80e`
      (PR #27), branch `feat/cern-oidc-native-role-observation-1a2-5b3`.
- [ ] Guarded installer confirms two existing production files and six new
      files; no dependencies, API, frontend or existing tests are modified.
- [ ] Original `exchange_callback`, `complete`, and the original live
      ID-token diagnostic retain their public signatures and behavior.
- [ ] New role path consumes one private browser/state/PKCE authorization
      attempt before any token exchange, and checks roles on that very token.
- [ ] No externally supplied verified token, role list, signing key, JWKS,
      role name, or access token is accepted as a callback input.
- [ ] Existing issuer, callback HTTP syntax, host/peer address, `session_state`,
      replay, cancellation, expiry, nonce, `at_hash` and TLS checks stay intact.
- [ ] Known role statuses are returned only as observations; unknown result
      types, malformed or contradictory claims fail closed.
- [ ] Default CLI execution is offline; only `--live` starts a real transaction.
- [ ] Live CLI prints only fixed status labels. No identifiers, tokens, browser
      URLs, claims, code/verifier, nonce, exception strings or tracebacks.
- [ ] Local unit/security tests pass using synthetic data, without CERN network.
- [ ] Full eight-gate diagnostics passes, with `PASS=8 FAIL=0 SKIPPED=0`.
- [ ] Review full diff, hashes and sanitized diagnostics before commit/push.
- [ ] Validate 13 PR checks, merge review, 13 post-merge checks and local
      eight-gate diagnostics before formal phase closure.
- [ ] A real CERN role observation is separately opt-in and only permitted
      after the source, tests and logs have been reviewed. It is NOT run in CI.

## Suggested local validation

```bash
uv run --locked ruff check --fix \
  src/asca/infrastructure/oidc_native_exchange.py \
  src/asca/infrastructure/oidc_native_lifecycle.py \
  scripts/check_cern_oidc_native_role_live.py \
  tests/unit/test_oidc_native_role_observation.py \
  tests/unit/test_cern_native_role_live_diagnostic.py \
  tests/security/test_oidc_native_role_observation_security.py

uv run --locked ruff format \
  src/asca/infrastructure/oidc_native_exchange.py \
  src/asca/infrastructure/oidc_native_lifecycle.py \
  scripts/check_cern_oidc_native_role_live.py \
  tests/unit/test_oidc_native_role_observation.py \
  tests/unit/test_cern_native_role_live_diagnostic.py \
  tests/security/test_oidc_native_role_observation_security.py

uv run --locked python -m pytest -q \
  tests/unit/test_oidc_native_role_observation.py \
  tests/security/test_oidc_native_role_observation_security.py \
  tests/unit/test_cern_native_role_live_diagnostic.py \
  tests/unit/test_oidc_native_exchange.py \
  tests/security/test_oidc_native_exchange_security.py \
  tests/unit/test_oidc_native_lifecycle.py \
  tests/security/test_oidc_native_lifecycle_security.py \
  tests/unit/test_cern_native_live_diagnostic.py \
  tests/security/test_cern_native_live_diagnostic_security.py \
  tests/unit/test_oidc_verified_role_observation.py \
  tests/security/test_oidc_verified_role_observation_security.py

uv run --locked python scripts/run_checks.py
uv run --locked python scripts/check_cern_oidc_native_role_live.py

git diff --check
git diff --stat
git status --short
```

Offline command result: `RESULT=OFFLINE_ONLY` with no network.
Full gates: `PASS=8 FAIL=0 SKIPPED=0` and `Gate: ELIGIBLE FOR REVIEW`.

## Explicit live operator check (only after code review)

```bash
uv run --locked python scripts/check_cern_oidc_native_role_live.py --live
```

Expected successful diagnostic completion, independent of role presence:

```text
STEP=CALLBACK_RECEIVED
ROLE_STATUS=CLAIMED | ABSENT | MFA_REQUIRED | LOA_REQUIRED | MFA_AND_LOA_REQUIRED
RESULT=ROLE_OBSERVATION_COMPLETE_NO_SESSION
```

The `ROLE_STATUS` line will contain only one of these fixed values; the pipe
notation above is documentation and is not literal output. Any failure is
sanitized and must be investigated separately. Never capture browser callbacks,
ID Tokens, bearer tokens, group lists or personal data for debugging.

## Next milestone

Review actual provider observations and design a separate production trust
boundary. Do not infer permissions from diagnostic statuses or enable an
ASCA authenticated session in this phase.
