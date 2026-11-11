# Phase 1A.2.5B2 acceptance: verified role observation composition

This offline increment adds role observation inside the existing signature and
claims verification pipeline. It does **not** add an authenticated ASCA session,
role-authorized principal, browser or CERN live probe.

## Acceptance criteria

- [ ] Clean `main` at `6f18235b914bbf7d70705be3e362652b29488b51` and new branch `feat/cern-oidc-verified-role-observation-1a2-5b2`.
- [ ] Guarded installer reports exactly one modification and four additions.
- [ ] Existing `check` inputs and `CheckedUntrustedCernOidcToken` result stay unchanged.
- [ ] `observe_role` accepts only unverified token response, trusted-policy inputs and metadata; never an externally prechecked signature or role observation.
- [ ] One pinned JWKS retrieval, then JWS signature and OIDC claims checks precede role inspection.
- [ ] Role inspection uses only the same verified ID Token and access token; `at_hash` is validated.
- [ ] No additional audiences, widened time tolerances, role grants or principals are introduced.
- [ ] Invalid signature, issuer, audience, nonce, expiry and `at_hash` fail before inspecting roles.
- [ ] Roles from unrelated clients, malformed roles and contradictions do not yield a `claimed` result.
- [ ] Results and errors contain no token, nonce, subject, credential, group or role details.
- [ ] Run focused integration/security regression tests, plus all eight quality gates.
- [ ] Review sanitized diagnostics, `git diff --check`, status and all changed paths before commit/push.
- [ ] No live `--live` command should run in CI or as part of this phase.
- [ ] Require 13 PR and 13 post-merge CI checks, then rerun local quality gates.

## Commands

```bash
uv run --locked ruff check --fix \
  src/asca/infrastructure/oidc_verification.py \
  tests/unit/test_oidc_verified_role_observation.py \
  tests/security/test_oidc_verified_role_observation_security.py
uv run --locked ruff format \
  src/asca/infrastructure/oidc_verification.py \
  tests/unit/test_oidc_verified_role_observation.py \
  tests/security/test_oidc_verified_role_observation_security.py

uv run --locked python -m pytest -q \
  tests/unit/test_oidc_verified_role_observation.py \
  tests/security/test_oidc_verified_role_observation_security.py \
  tests/unit/test_oidc_verification.py \
  tests/security/test_oidc_verification_security.py \
  tests/unit/test_oidc_cern_role_claims.py \
  tests/security/test_oidc_cern_role_claims_security.py

uv run --locked python scripts/run_checks.py

git add -N \
  tests/unit/test_oidc_verified_role_observation.py \
  tests/security/test_oidc_verified_role_observation_security.py \
  docs/adr/0029-verified-cern-oidc-role-observation.md \
  docs/development/phase1a2-5b2-acceptance.md

git diff --check
git diff --stat
git status --short
```

Required result: `PASS=8 FAIL=0 SKIPPED=0` and `Gate: ELIGIBLE FOR REVIEW`.
Do not commit or push before reviewing both focused and complete diagnostics.

## Next increment

Add the strictly opt-in and privacy-preserving role-status check within the
single-use native transaction. Confirm the actual CERN ID Token role shape
without logging IDs, tokens, usernames, groups, or callback URLs. Never
promote `claimed` to authority without a distinct reviewed trust boundary.
