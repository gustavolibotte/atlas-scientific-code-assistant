# Phase 1A.2.5A acceptance: native CERN OIDC live diagnostic

## Scope

Validate that the registered public CERN client can use the existing ASCA default adapters for one real browser authorization, code+PKCE token exchange and ID-token signature/claims check. This is a diagnostic, **not** CERN login enablement.

## Acceptance gates

- [ ] Start from clean `main` at `3eb00ee79b07f671ee3c1e58cbf6c69fdcb02dd4` and new branch `feat/cern-oidc-native-live-probe-1a2-5a`.
- [ ] Apply the guarded initial candidate and narrowly scoped callback correction; among existing production files, only `src/asca/infrastructure/oidc_native_callback.py` changes. No new routes, dependencies, frontend, or existing test files modified.
- [ ] Default CLI invocation prints `RESULT=OFFLINE_ONLY` without network, browser, socket or secrets.
- [ ] The explicit `--live` path binds the actual OS socket before composing a default-only CERN exchange and uses a protected private browser binding.
- [ ] Successful real flow reports only `RESULT=ID_TOKEN_CHECK_PASSED_NO_SESSION` and states that ASCA session, role authorization and chATLAS access are disabled.
- [ ] All error paths are sanitized; no exception repr/traceback, browser URLs, callback parameters, tokens or PII are printed.
- [ ] Listener and opaque pending attempts are closed/revoked after success, denial, timeout, or browser failure.
- [ ] Do not use `--live` in CI, PR, offline unit/security tests, or automated diagnostics. Never save live CERN HTTP responses.
- [ ] Run focused tests and the official eight-gate diagnostic suite with `PASS=8 FAIL=0 SKIPPED=0`.
- [ ] Review test count, code diff, coverage and all changed paths before commit/push.
- [ ] After reviewing the real live result, require all 13 PR CI jobs and all 13 post-merge jobs before final closure; rerun local eight gates post-merge.
- [ ] Explicitly keep `cern_sso` and `chatlas` capabilities as `not_implemented`.

## Verification commands

```bash
uv run --locked python scripts/check_cern_oidc_native_live.py
uv run --locked pytest -q tests/unit/test_cern_native_live_diagnostic.py tests/security/test_cern_native_live_diagnostic_security.py
uv run --locked ruff check --fix scripts/check_cern_oidc_native_live.py tests/unit/test_cern_native_live_diagnostic.py tests/security/test_cern_native_live_diagnostic_security.py
uv run --locked ruff format scripts/check_cern_oidc_native_live.py tests/unit/test_cern_native_live_diagnostic.py tests/security/test_cern_native_live_diagnostic_security.py
uv run --locked ruff check src tests scripts
uv run --locked ruff format --check src tests scripts
uv run --locked mypy src
uv run --locked python scripts/run_checks.py

git diff --check
git status --short
```

## Optional live execution (only after local review)

```bash
uv run --locked python scripts/check_cern_oidc_native_live.py --live
```

The live command starts an authorization in the user's normal CERN browser session. Its terminal output must contain no tokens or authorization query strings. A blank browser page with HTTP 202 can be normal for the existing listener; the terminal status is authoritative for the diagnostic result, **not** for user authentication.

## CERN callback compatibility correction

- [ ] Confirmed the independent live callback shape probe reported both `iss`
  and `session_state`, four recognized query parameters, and no forbidden headers.
- [ ] New parser explicitly permits optional, bounded `session_state` but never
  uses or exposes it as identity, binding, session or authorization evidence.
- [ ] Duplicate keys, unknown keys, malformed/oversized `session_state`, and
  extra query parameters remain rejected.
- [ ] Focused new tests pass before repeating the full eight-gate suite.
- [ ] Explicit real CERN diagnostic reaches `STEP=CALLBACK_RECEIVED`; the token
  exchange/verification stage is assessed separately. No live data in CI logs.

## CERN OIDC `at_hash` binding correction

- [ ] Real CERN claim-shape probe confirmed `at_hash=YES`, `c_hash=NO`,
  `s_hash=NO`, and rejection at the prior unbound-hash rule.
- [ ] Changed **only** `src/asca/application/oidc_claims.py` and
  `src/asca/infrastructure/oidc_verification.py` among additional tracked
  production modules; no new routes, dependencies, or frontend changes.
- [ ] Optional `at_hash` is validated against the access token from the same
  parsed response (SHA-256 half-digest, unpadded base64url, constant-time check).
- [ ] Missing/wrong/swapped tokens, malformed hashes and duplicates fail closed;
  `c_hash`/`s_hash` still reject and no session or role is created.
- [ ] New cryptographic pipeline tests cover RS256, PS256 and ES256.
- [ ] Focused tests and all eight quality gates pass on the operator's Mac.
- [ ] `--live` is explicitly rerun; note any additional failure separately.
- [ ] No commit or push until live diagnostics and diff have been reviewed.
