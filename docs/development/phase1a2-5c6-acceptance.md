# Phase 1A.2.5C6 acceptance — implementation prerequisite traceability

C6 is offline planning only. It introduces no runtime OIDC, policy adapter,
CERN network access, login, sessions, protected routes or delegated resources.

## Acceptance checklist

- [ ] Base is clean `main` at `d3491923b38d59cdecf2b3cbb04d11a151101e65`
      (PR #33) on `feat/cern-implementation-readiness-review-1a2-5c6`.
- [ ] Guarded installer adds exactly six files with checksums and no changes.
- [ ] ADR 0036 distinguishes offline test readiness from operator evidence,
      independent approval and actual deployment readiness.
- [ ] Exactly G1–G10 occur once, in order, with explicit evidence-owner roles,
      offline preparation, independent proof requirements and test methods.
- [ ] All ten gate rows stay blocked; no status of APPROVED, READY or ALLOW.
- [ ] Cross-contract checker rejects forged approvals, duplicate keys, wrong
      gates, altered C2 statuses, symlinks and oversized or malicious input.
- [ ] C2/C3 evidence remains unverified; C4 retains 20 DENY cases; C5 retains
      eight stages, ten gates, three disabled resource boundaries.
- [ ] Checker output never exposes source documents or operator references.
- [ ] No existing production files or dependencies are changed.
- [ ] Focused tests and all eight quality gates pass without skips.
- [ ] Git diff contains exactly six additions and `git diff --check` passes.
- [ ] Before merge: 13 PR checks. After merge: 13 main checks and local 8 gates.

## Commands

```bash
uv run --locked ruff check src tests scripts
uv run --locked ruff format --check src tests scripts
uv run --locked python -m pytest -q \
  tests/security/test_oidc_c6_implementation_readiness_security.py \
  tests/security/test_oidc_c5_authorization_contract_security.py \
  tests/security/test_oidc_c4_negative_policy_security.py
uv run --locked python scripts/check_cern_web_implementation_readiness.py
uv run --locked python scripts/run_checks.py
```

The checker must return `RESULT=IMPLEMENTATION_REVIEW_REQUIRED_NO_GRANT`.
The full quality gate must finish with `PASS=8 FAIL=0 SKIPPED=0` and
`Gate: ELIGIBLE FOR REVIEW`.

**Stop condition:** no offline matrix, JSON value, CLI exit code, synthetic
fixture or successful CI build is authorization to enable protected features.
