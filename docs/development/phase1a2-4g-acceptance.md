# Phase 1A.2.4G acceptance: replay-resistant web BFF authorization binding

## Scope

Bind a locally issued, browser-protected single-use authorization attempt to the existing non-authenticating CERN OIDC signature-and-claims verification pipeline. Reuse the existing cookie reader, `OidcAuthorizationService` and in-memory atomic attempt store. Do not add login routes, trusted identities, sessions, external stores, token exchange, live CERN requests, or dependencies.

## Acceptance checklist

- [ ] Start from clean `main` at PR #15 squash merge `564dece`, after remote 13/13 post-merge and local 8/8 quality gates.
- [ ] Create branch `feat/oidc-replay-safe-authorization-binding-1a2-4g`, add exactly six source/test/docs files, and preserve every existing tracked file and lockfile.
- [ ] Reject native registration and forged, invalid or non-CERN configuration prior to creating a browser attempt.
- [ ] Generate new state/nonce/PKCE/verifier and return a `__Host-` BFF authorization cookie with appropriate flags; no credentials are logged or returned as an identity.
- [ ] Resolve `expected_client_id` from the validated local configuration only; resolve `expected_nonce` only from a stored authorization attempt that has been atomically consumed using the original browser binding and `state`.
- [ ] Reject cookie swapping, state mismatch, missing cookies and expired attempts; do not consume an unrelated attempt on a mismatch.
- [ ] Reject replay after success, after downstream verification failure and under concurrent callback attempts.
- [ ] Sanitize all expected errors, including verifier rejection, and never expose nonce, browser binding, token or authorization code in exception text or `repr`.
- [ ] Run real synthetic end-to-end signing checks for RS256, PS256 and ES256 with a test-only HTTP opener; no live CERN network calls.
- [ ] Do not claim that supplying token-response data proves a successful code exchange; no actual code-to-token binding is implemented.
- [ ] Do not claim that local client metadata proves official CERN registration, or that the in-memory store provides multiworker atomicity.
- [ ] `uv run --locked ruff check src tests scripts`, `ruff format --check`, mypy, focused tests and `uv run --locked python scripts/run_checks.py` must pass with 8 PASS / 0 FAIL / 0 SKIPPED.
- [ ] Confirm diagnostic ZIP, `git diff --check`, exactly six new files, and no dependency changes before commit/push.
- [ ] Require 13/13 GitHub Actions jobs on PR and after merge before closing this phase.

## Local validation commands

```bash
uv run --locked ruff check --select I --fix src/asca/domain/oidc_authorization_binding.py src/asca/infrastructure/oidc_authorization_binding.py tests/unit/test_oidc_authorization_binding.py tests/security/test_oidc_authorization_binding_security.py
uv run --locked ruff format src/asca/domain/oidc_authorization_binding.py src/asca/infrastructure/oidc_authorization_binding.py tests/unit/test_oidc_authorization_binding.py tests/security/test_oidc_authorization_binding_security.py
uv run --locked ruff check src tests scripts
uv run --locked pytest -q tests/unit/test_oidc_authorization_binding.py tests/security/test_oidc_authorization_binding_security.py
uv run --locked python scripts/run_checks.py
git diff --check
git diff --stat
git status --short
```

## Mandatory future security work

The BFF must perform a real authorization-code exchange under an officially confirmed client registration, bind the response to the consumed authorization attempt, use a strongly consistent multiworker store, handle cookie clearing on failures, enforce rate limiting, and create sessions only from a dedicated, independently reviewed trusted verification root. None of that is completed in this phase. CERN SSO must remain `not_implemented`.
