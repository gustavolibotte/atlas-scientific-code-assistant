# Phase 1A.2.4B acceptance: isolated, pinned CERN JWKS HTTPS transport

## Scope

Add a single constrained JWKS HTTPS fetch adapter, an immutable opaque response contract, adversarial offline tests and documentation. There are no changes to existing application modules, no live CERN calls, no JWT signature verification, no account authorization and no mounted login/session endpoints. `cern_sso` remains `not_implemented`.

## Acceptance criteria

- [ ] Begin from clean `main` at the reviewed PR #10 squash merge `052f753`, after 13/13 post-merge jobs and 8/8 local quality gates.
- [ ] Work in `feat/oidc-jwks-https-retrieval-1a2-4b` and add only six new files.
- [ ] Require pinned CERN issuer and exact `/protocol/openid-connect/certs` URI, with approved, unambiguous asymmetric signing algorithms; fail before opening a network connection on manipulated metadata.
- [ ] Issue one GET to the literal HTTPS destination. Default opener must verify TLS hostname/certificates, disable environment proxies and reject redirects. Never send cookies, authentication headers or credentials.
- [ ] Enforce bounded timeouts, HTTP status 200, JSON/JWK-set media type, response size <= 262,144 bytes and strict `Content-Length` equality when declared.
- [ ] Reject duplicate/malformed headers, compressed HTTP responses, ambiguous `Content-Length`/`Transfer-Encoding`, non-byte bodies and invalid status codes.
- [ ] Preserve opaque JWKS bytes and an explicitly unverified response type; require later offline parsing and cryptographic verification before identity use.
- [ ] Use fake injected openers and synthetic data exclusively in tests. No live CERN calls, production routes, new dependencies or existing source changes.
- [ ] Run focused tests and the full existing suite; `uv run python scripts/run_checks.py` reports 8 PASS, 0 FAIL, 0 SKIPPED and backend branch coverage >= 85%.
- [ ] Inspect complete local diagnostics and `git diff --check`, `git diff --stat`, `git status --short` before commit/push.
- [ ] Require 13/13 successful remote CI jobs on the PR and again on `main` after merge.

## Local commands

```bash
uv run ruff format src/asca/domain/oidc_jwks_http.py src/asca/infrastructure/oidc_jwks_http.py tests/unit/test_oidc_jwks_http.py tests/security/test_oidc_jwks_http_security.py
uv run ruff check src tests scripts
uv run pytest -q tests/unit/test_oidc_jwks_http.py tests/security/test_oidc_jwks_http_security.py
uv run python scripts/run_checks.py
git diff --check
git diff --stat
git status --short
```

## Security notice

Do not invoke this adapter against CERN with live data during this stage. No user-provided or JWT-provided retrieval URL is allowed. Public JWKS bytes are not a verified signature, an authenticated identity, a session or proof of authorization to read restricted CERN material. Never send authorization codes, tokens, cookies, client secrets or `.env` files to diagnostics or GitHub.
