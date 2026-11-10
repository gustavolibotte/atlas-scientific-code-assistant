# Phase 1A.2.3C acceptance: strict unverified OIDC token-response parsing

## Scope

Add an **offline** token-response parser and non-authenticating result contract. No HTTP calls, no cryptographic identity validation, no session creation, no production login routes and no dependency changes. `cern_sso` must remain `not_implemented`.

## Acceptance criteria

- [ ] Begin with clean `main` after approved PR #8 squash merge `efd8a25` and completed 13/13 post-merge CI.
- [ ] Work on `feat/oidc-token-response-validation-1a2-3c`. Add only the six candidate files; do not modify existing modules.
- [ ] Reject malformed, oversized or non-object JSON, duplicate object members at all levels, invalid UTF-8 and nonstandard numeric constants.
- [ ] Require valid access-token text, compact JWS-shaped ID token and case-insensitive Bearer token type; never consider syntax to be signature or identity verification.
- [ ] Accept missing `expires_in` per RFC 6749; reject provided invalid, negative, zero, noninteger or excessively large expiry values.
- [ ] Accept bounded optional refresh-token and scope fields; do not store tokens, make refresh requests or authorize from scopes.
- [ ] Reject OAuth error fields on 200 responses; ignore unknown provider extensions without assigning privilege or creating sessions.
- [ ] Keep all credential fields secret in repr, sanitize exceptions, and assert that parser code cannot contact a network.
- [ ] Focused tests and all existing tests pass; `uv run python scripts/run_checks.py` produces 8 PASS, 0 FAIL, 0 SKIPPED and branch coverage >= 85%.
- [ ] Review full local diagnostics before commit/push/PR; then require 13/13 remote CI jobs on the PR and post-merge `main`.

## Local commands

```bash
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
uv run pytest -q tests/unit/test_oidc_token_response.py tests/security/test_oidc_token_response_security.py
uv run python scripts/run_checks.py
git diff --check
git diff --stat
git status --short
```

## Security notice

Never upload CERN access tokens, ID tokens, refresh tokens, authorization codes, cookies, registered client secrets or `.env` files. All test credentials are synthetic and no provider calls occur. Token parsing cannot identify or log in a user; signature, issuer, audience, nonce, expiry, replay and authorization validation remain mandatory later steps.
