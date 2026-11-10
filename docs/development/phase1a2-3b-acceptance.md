# Phase 1A.2.3B acceptance: isolated native-public HTTPS token transport

## Scope

A guarded, deliberately **unmounted** infrastructure adapter that can make a single bounded HTTPS token POST when explicitly called. No login route, actual CERN integration, public user workflow, token validation, authenticated principal, session or confidential BFF client authentication is added.

## Acceptance criteria

- [ ] Start from clean `main` at approved PR #7 squash merge `fe20f98`, with 13 post-merge CI jobs passing.
- [ ] Keep new changes in branch `feat/oidc-token-https-transport-1a2-3b`; do not overwrite any existing file.
- [ ] Reject requests to arbitrary URLs, HTTP endpoints, fragments, query strings, alternate same-origin paths or forged fields.
- [ ] For a native public registration, require an exact client ID, exact callback, five permitted form fields and a structurally valid PKCE verifier.
- [ ] Use TLS verification, no redirects, no ambient proxy configuration, a bounded timeout and a 65,536-byte maximum response.
- [ ] Reject HTTP errors, 3xx redirections, inconsistent Content-Length, duplicate headers and compressed or non-JSON responses without echoing secrets.
- [ ] Keep response bytes unverified and hidden from `repr`; never infer identity from an HTTP 200 response.
- [ ] No real CERN network call in the new tests. Do not provide live codes, tokens, cookies, client registrations or `.env` files.
- [ ] Preserve production API routes and `cern_sso: not_implemented`; no runtime dependencies or existing source files changed.
- [ ] Focused tests and full existing suite pass. `uv run python scripts/run_checks.py`: 8 PASS, 0 FAIL, 0 SKIPPED; backend branch coverage >=85%.
- [ ] Review complete local diagnostics before commit, push or PR. Require 13/13 GitHub Actions jobs on PR and on `main` after merge.

## Commands

```bash
uv run pytest -q tests/unit/test_oidc_token_http.py tests/security/test_oidc_token_http_security.py
uv run python scripts/run_checks.py
git diff --check
git status --short
```

## Security notice

The transport is intentionally not mounted or called by any ASCA production route. Do not invoke it with live CERN authorization codes; this phase validates its behavior entirely against an injected fake opener. `UnverifiedOidcTokenHttpResponse` is **not** a token parser, verified ID token, or session.
