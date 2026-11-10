# Phase 1A.2.2C acceptance: unmounted OIDC HTTP transport boundary

## Scope

Only HTTPS BFF request validation, bounded raw callback parsing, duplicate-header rejection, and a generic cookie-clearing unavailable response. **No new route** is mounted on the actual FastAPI app. No real CERN login, token exchange, session creation, or network access is permitted.

## Acceptance criteria

- [ ] Begin from clean `main` after the PR #5 squash merge (`ed33496`) with successful local and remote CI.
- [ ] Reject non-HTTPS requests, native client mode, wrong/duplicate Host headers and unregistered callback paths.
- [ ] Do not use untrusted `X-Forwarded-Proto` or `Forwarded` headers to bypass HTTPS checks.
- [ ] Reject duplicate and malformed query fields, invalid state, ambiguous code/error combinations, invalid encodings and oversized requests.
- [ ] Reject missing, duplicate and malformed Cookie headers; never expose cookie or callback parameters in errors or object representations.
- [ ] An unavailable callback returns a generic response with an expiring `__Host-` binding cookie and `no-store` headers.
- [ ] Existing production app routes and capability status remain unchanged. No login or callback route exists.
- [ ] All new tests are network-free and include HTTP-level ASGI fixtures rather than CERN secrets.
- [ ] `uv run python scripts/run_checks.py`: 8 PASS, 0 FAIL, 0 SKIPPED and branch coverage >=85%.
- [ ] Full local diagnostic bundle reviewed before commit/push/PR.
- [ ] All 13 CI jobs pass on the PR and again on `main` after merge.

## Local verification

```bash
uv run pytest -q tests/security/test_oidc_http_transport.py tests/contract/test_oidc_http_contract.py
uv run python scripts/run_checks.py
git diff --check
git status --short
```

## Security reminder

Do not share CERN credentials, client IDs from real registrations, authorization codes, tokens, cookies or `.env` files. The test fixtures use fake callback URLs and placeholder values; no CERN network request is made.
