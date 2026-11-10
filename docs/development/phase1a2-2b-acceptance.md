# Phase 1A.2.2B acceptance: HTTPS BFF browser-binding contract

## Scope

Add **only** an offline browser-binding cookie policy and a callback correlation adapter for future HTTPS WEB_BFF deployments. Do not add routes, real CERN login, native desktop cookies, token exchange, token signature checks, sessions, new dependencies or outbound requests.

## Acceptance criteria

- [ ] Begin from clean `main` containing approved PR #4 (`18d5046`), with all 13 post-merge GitHub Actions jobs successful.
- [ ] Use a short-lived opaque, host-only `__Host-` cookie; require `Secure; HttpOnly; Path=/; SameSite=Lax` and no `Domain`.
- [ ] Restrict the binding cookie contract to the `WEB_BFF` client mode; reject native loopback.
- [ ] Only use the browser cookie to correlate a **pre-authentication** authorization attempt; it cannot create a user or session.
- [ ] Reject missing, duplicate, oversized, control-character, non-ASCII, and malformed `Cookie` headers; reject malformed binding values without echoing secrets.
- [ ] Confirm callback state and cookie binding are checked by the single-use attempt store. Replay and wrong-browser cases fail.
- [ ] Provide a clearing header suitable for success and error callback paths; actual HTTP integration is still absent.
- [ ] No CERN credentials, tokens, passwords, raw authorization headers, or real portal registration details are needed.
- [ ] All previous API capability states and login status remain unchanged.
- [ ] `uv run python scripts/run_checks.py` reports 8 PASS, 0 FAIL, 0 SKIPPED; branch coverage >= 85%.
- [ ] Review diagnostic ZIP and code diff before committing or pushing.
- [ ] All 13 CI jobs pass on the PR before merge, then on `main` afterward.

## Local verification

```bash
uv run pytest -q \
  tests/unit/test_oidc_browser_cookie.py \
  tests/security/test_oidc_browser_binding.py
uv run python scripts/run_checks.py
git diff --check
git status --short
```

## Security reminder

A cookie is not evidence of a CERN account. The callback result remains an **unverified authorization-code grant**. The user must not supply CERN passwords, client secrets, authorization codes, tokens or cookies to diagnostic archives, GitHub issues or chat.
