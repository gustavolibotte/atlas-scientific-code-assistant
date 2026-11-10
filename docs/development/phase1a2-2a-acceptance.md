# Phase 1A.2.2A acceptance: registered-client configuration preflight

## Scope

This is **only** an offline configuration and trust-policy increment. It does **not** register an OIDC client, contact CERN, authenticate a user, exchange a code, verify a JWT or establish sessions. It must be applied **after Phase 1A.2.1 has been merged and validated on `main`**.

## Acceptance criteria

- [ ] Begin from a clean `main` containing the approved Phase 1A.2.1 merge.
- [ ] No dependency on `atlas-rag`, secrets, network, or new runtime packages.
- [ ] The client mode is explicit: native HTTP loopback-IP callback with port or hosted HTTPS DNS BFF callback.
- [ ] Callback configurations reject remote HTTP, credentials, query strings, fragments, wildcards, encoded ambiguity, traversal, non-loopback callback hosts, and invalid ports.
- [ ] `client_id` never appears in the registration object's `repr`.
- [ ] Scopes are limited to approved basic OIDC values; `openid` is mandatory.
- [ ] The offline bridge rejects fake/mismatched issuers, alternate origins, absent PKCE S256 and unsupported signing algorithms.
- [ ] The old identity status and all capability flags remain unchanged: CERN login is **not implemented**.
- [ ] Tests pass without CERN access, including previous identity/discovery tests and all frontend tests.
- [ ] `uv run python scripts/run_checks.py` reports all eight checks passing, zero skipped, and coverage >= 85%, including branch coverage.
- [ ] Full diagnostics archive reviewed **before** commit, push, or pull request, following the established ASCA workflow.
- [ ] Pull request passes all nine backend matrix jobs, both frontend jobs and both aggregate quality gates before merge.
- [ ] Post-merge `main` workflows pass and only then may the next increment begin.

## Validate on Mac/Linux

```bash
uv run pytest -q tests/unit/test_oidc_client_registration.py \
  tests/security/test_oidc_client_preflight.py
uv run python scripts/run_checks.py
git diff --check
git status --short
```

## Evidence and security handling

Do not share portal client secrets, cookies, authorization codes, refresh tokens or `.env` files. An arbitrary value such as `example-not-registered` in tests must never be presented as an issued CERN client ID. The diagnostic ZIP retains its existing name, `diagnostics/phase0-diagnostics.zip`, for compatibility with the project's established checks.
