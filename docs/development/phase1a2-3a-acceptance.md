# Phase 1A.2.3A acceptance: offline native-public token request

## Scope

This increment **only** prepares a sensitive, unsent Authorization Code + PKCE token request for a native public CERN OIDC client. It must not connect to CERN, implement a token adapter, accept client secrets, expose login endpoints, validate ID tokens, authenticate accounts, establish sessions or introduce runtime dependencies.

## Acceptance criteria

- [ ] Start from clean `main` containing approved PR #6 squash merge `79a5efc`, with successful post-merge local and remote CI.
- [ ] The feature branch is `feat/oidc-public-token-request-1a2-3a` and the installer does not overwrite existing files.
- [ ] Only `NATIVE_LOOPBACK` registration is accepted; `WEB_BFF` fails closed pending a client authentication decision.
- [ ] Existing CERN issuer, metadata, PKCE S256 and callback trust policies are reused rather than bypassed.
- [ ] Exact redirect URI equality is enforced; invalid codes, verifiers and nonces fail without echoing secrets.
- [ ] The prepared POST contains the five permitted form fields and fixed, secret-free request headers.
- [ ] Neither the form body nor nonce appears in `repr`; no network, token parser, auth route or session is introduced.
- [ ] The existing CERN SSO capability remains `not_implemented`, and `/api/v1/identity/login`, `/callback`, `/token` remain unmounted.
- [ ] Focused tests and all existing tests pass. `uv run python scripts/run_checks.py`: 8 PASS, 0 FAIL, 0 SKIPPED, branch coverage >= 85%.
- [ ] Full local diagnostic ZIP is reviewed before commit, push and PR.
- [ ] After PR review, 13 GitHub Actions jobs pass on the PR and post-merge `main`.

## Local commands

```bash
uv run ruff format \
  src/asca/domain/oidc_token_request.py \
  src/asca/application/oidc_token_request.py \
  tests/unit/test_oidc_token_request.py \
  tests/security/test_oidc_token_request_security.py
uv run pytest -q \
  tests/unit/test_oidc_token_request.py \
  tests/security/test_oidc_token_request_security.py
uv run python scripts/run_checks.py
```

## Evidence handling

Do not upload authorization codes, live PKCE verifiers, client secrets, cookies, ID tokens, access tokens or `.env` files to GitHub, diagnostics or chat. All test values are synthetic. The diagnostic ZIP remains `diagnostics/phase0-diagnostics.zip`.
