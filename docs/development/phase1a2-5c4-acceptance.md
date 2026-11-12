# Phase 1A.2.5C4 acceptance: independent review and negative policy requirements

C4 adds a synthetic negative-policy test-vector contract, its strictly offline
validator, ADR 0034, an independent review protocol and security tests.
**It does not authorize users or attest production readiness.**

## Scope and review checklist

- [ ] Start from clean `main` commit `b87ca8c3078df39ba4f918ab8b92ad49d54e4c3f`
      and the `feat/cern-independent-review-negative-policy-1a2-5c4` branch.
- [ ] Guarded installer adds exactly six new files, with no modifications.
- [ ] ADR 0034 distinguishes evidence submission, independent review,
      application-owner decision and production deployment approval.
- [ ] The negative-case file contains the complete versioned set of synthetic
      DENY scenarios, with no ALLOW, APPROVED, session or access grant state.
- [ ] Offline checker rejects malformed JSON, duplicate members, unexpected
      fields, unsafe paths, invalid cases, omitted cases or substituted gates.
- [ ] Checker verifies C2/C3 committed *snapshot* remains unapproved and
      emits only fixed non-sensitive labels; no reference is dereferenced.
- [ ] Test that even a complete collection of negative cases cannot authorize
      an ASCA principal, issue a session or grant chATLAS access.
- [ ] No live CERN request, new dependency, production/API/frontend code,
      credential capture, session storage or secret-bearing artifact.
- [ ] Focused tests and all eight quality gates pass, with no skipped gate.
- [ ] `git diff --check` passes; diff shows six new files only.
- [ ] PR CI 13/13, post-merge CI 13/13 and local gates 8/8 before closing C4.

## Commands

```bash
uv run --locked ruff check src tests scripts
uv run --locked ruff format --check src tests scripts
uv run --locked python -m pytest -q \
  tests/security/test_oidc_c4_negative_policy_security.py \
  tests/security/test_oidc_c3_operator_evidence_intake_security.py \
  tests/security/test_oidc_c2_web_assurance_boundary_security.py \
  tests/security/test_oidc_authorization_boundary_security.py
uv run --locked python scripts/check_cern_web_negative_policy.py
uv run --locked python scripts/check_cern_web_operator_intake.py
uv run --locked python scripts/run_checks.py

git add -N \
  docs/adr/0034-independent-evidence-review-and-negative-policy-spec.md \
  docs/security/cern-web-independent-review-protocol.md \
  docs/security/cern-web-negative-policy-cases.json \
  docs/development/phase1a2-5c4-acceptance.md \
  scripts/check_cern_web_negative_policy.py \
  tests/security/test_oidc_c4_negative_policy_security.py

git diff --check
git diff --stat
git status --short
```

The checker must return `RESULT=INDEPENDENT_REVIEW_REQUIRED_NO_GRANT` and
`G1=BLOCKED`, `G6=BLOCKED`, `G7=BLOCKED`.
Full suite: `PASS=8 FAIL=0 SKIPPED=0` and `Gate: ELIGIBLE FOR REVIEW`.

## Stop condition

Do not create an approval record in code or accept a user-supplied JSON file
as proof of provider configuration. The blocked C2 and C3 snapshots are not
live provider checks. A human reviewer must separately verify all relevant
original evidence and the implemented deployment before any future login or
permission code can be enabled.
