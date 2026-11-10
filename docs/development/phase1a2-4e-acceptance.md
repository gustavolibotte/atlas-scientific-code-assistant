# Phase 1A.2.4E acceptance: strict offline OIDC ID-token claims validation

## Scope

Validate claims from a signature-checked but **untrusted-provenance** JWS against explicitly supplied issuer/client/nonce/time policies. Do not fetch JWKS, create a verified identity, add login routes, create sessions, authorize CERN resources, or modify existing modules/dependencies. `cern_sso` remains `not_implemented`.

## Acceptance criteria

- [ ] Start from clean `main` at reviewed PR #13 squash merge `da7cc52`, after remote 13/13 post-merge jobs and local 8/8 quality gates.
- [ ] Work in `feat/oidc-id-token-claims-validation-1a2-4e` and add exactly six source/test/documentation files; do not overwrite existing files or change lockfiles/dependencies.
- [ ] Require a signature-checked JWS data container but explicitly avoid treating its forgeable Python type as proof of cryptographic provenance.
- [ ] Parse strict bounded UTF-8 JSON, reject duplicate nested members and non-finite constants, and sanitize all errors.
- [ ] Check exact CERN issuer, bounded ASCII subject, exact expected client audience, restricted additional audiences, mandatory `azp` on multi-audience tokens and exact nonce bound to the pending flow.
- [ ] Validate integer `exp`, `iat`, optional `nbf` and `auth_time`; enforce clock-skew and token-lifetime policy with a separately supplied clock.
- [ ] Reject unvalidated `at_hash`, `c_hash`, `s_hash`; ignore other unknown claims without assigning authority.
- [ ] Hide returned claims in `repr` and never produce `VerifiedIdentity`, sessions, roles, permissions or HTTP calls.
- [ ] Use only synthetic data. Include genuine offline signing-and-claims integration tests for RS256, PS256 and ES256.
- [ ] Run focused tests and the existing suite. `uv run --locked python scripts/run_checks.py` must yield 8 PASS, 0 FAIL, 0 SKIPPED and at least 85% global backend branch coverage.
- [ ] Verify `git diff --check`, `git diff --stat`, full diagnostics and local test coverage before any commit or push.
- [ ] Require all 13 remote GitHub Actions jobs on the PR and post-merge `main` before final phase acceptance.

## Commands

```bash
uv run --locked ruff check --select I --fix src/asca/application/oidc_claims.py tests/unit/test_oidc_claims.py tests/security/test_oidc_claims_security.py
uv run --locked ruff format src/asca/domain/oidc_claims.py src/asca/application/oidc_claims.py tests/unit/test_oidc_claims.py tests/security/test_oidc_claims_security.py
uv run --locked ruff check src tests scripts
uv run --locked pytest -q tests/unit/test_oidc_claims.py tests/security/test_oidc_claims_security.py
uv run --locked python scripts/run_checks.py
git diff --check
git diff --stat
git status --short
```

## Security notice

No CERN accounts, production JWTs, authorization codes, browser bindings, session cookies or `.env` files belong in tests, logs or GitHub. Even passing claims validation is not user authentication before verified key provenance and replay-safe flow orchestration.
