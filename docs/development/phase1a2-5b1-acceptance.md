# Phase 1A.2.5B1 acceptance: CERN application role-claim policy

This is an intentionally **offline** first increment of Phase 1A.2.5B.
It does not enable role authorization or inspect a live CERN token.

## Acceptance criteria

- [ ] Base commit is `200739d5d6faf5bd12a45c6e35f080e1548b1c85` (`main`
      after PR #25), with a clean worktree and new branch
      `feat/cern-oidc-role-claims-1a2-5b1`.
- [ ] Installer reports six verified additions and no modifications.
- [ ] Reuses existing strict OIDC claim checks before inspecting roles.
- [ ] Only `resource_access[expected_client_id].roles` is considered for the
      selected role; claims for other clients cannot authorize ASCA.
- [ ] Explicitly rejects malformed/duplicate roles, inconsistent `cern_roles`,
      contradictory MFA/LoA-missing hints, invalid nonce/audience/time, and
      unbound or incorrect `at_hash` values.
- [ ] MFA/LoA-missing hints yield distinct non-authoritative statuses.
- [ ] `claimed` remains non-authoritative; never return or create a principal,
      authenticated session, authorization grant, or chATLAS capability.
- [ ] No networking or credential handling occurs; no production endpoints,
      existing files, or dependencies change.
- [ ] New focused unit and adversarial tests pass; full eight-gate quality
      suite passes with zero skipped gates.
- [ ] Operator reviews diff and sanitized diagnostics before commit/push.
- [ ] PR CI and post-merge CI must pass before phase closure.

## Local commands

```bash
uv run --locked ruff check --fix \
  src/asca/domain/oidc_role_claims.py \
  src/asca/application/oidc_role_claims.py \
  tests/unit/test_oidc_cern_role_claims.py \
  tests/security/test_oidc_cern_role_claims_security.py
uv run --locked ruff format \
  src/asca/domain/oidc_role_claims.py \
  src/asca/application/oidc_role_claims.py \
  tests/unit/test_oidc_cern_role_claims.py \
  tests/security/test_oidc_cern_role_claims_security.py
uv run --locked python -m pytest -q \
  tests/unit/test_oidc_cern_role_claims.py \
  tests/security/test_oidc_cern_role_claims_security.py \
  tests/unit/test_oidc_claims.py \
  tests/security/test_oidc_claims_security.py
uv run --locked python scripts/run_checks.py

git diff --check
git diff --stat
git status --short
```

Expected gate summary: `PASS=8 FAIL=0 SKIPPED=0`. Only after
review of local output should a commit be considered.

## Next increment

Bind the role observation to the already verified, single-use live CERN
native transaction without accepting a caller-fabricated token, and run an
opt-in provider check that emits only role-status codes. Then review whether
an actual authorization capability can be safely established; the identity
and session boundary remains outside this increment.
