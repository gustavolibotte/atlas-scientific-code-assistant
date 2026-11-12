# Phase 1A.2.5C3 acceptance — offline CERN operator evidence intake

C3 turns the G1/G6/G7 operator follow-up from ADR 0032 into a strictly
non-authoritative, offline evidence-intake contract. **It does not implement
CERN login, verify portal registrations, attest MFA/LoA, issue sessions or
grant ASCA/chATLAS authorization.**

## Acceptance checklist

- [ ] Base clean `main` at `aa6e7a676bfa1e241e73c05c07a89c25ceb9b6c8`
      (PR #30); feature branch `feat/cern-web-operator-evidence-intake-1a2-5c3`.
- [ ] Guarded installer adds exactly six files, with no existing modifications.
- [ ] ADR 0033 distinguishes claimed, submitted, independently reviewed and
      production-trusted evidence, without accepting a forged approval.
- [ ] Default JSON template contains only missing evidence states for G1/G6/G7.
- [ ] All references are opaque, non-secret and never displayed by the CLI.
- [ ] Validator is stdlib-only, local, size-bounded, fails closed on ambiguous,
      duplicated, extra, malformed or symlinked input.
- [ ] A structurally valid record always requires independent operator review,
      including if every gate has a reference.
- [ ] No live CERN operation, new dependency, production or API change,
      credential capture, session or external resource access is introduced.
- [ ] Focused offline tests and all eight quality gates pass with no skips.
- [ ] `git diff --check` is clean and the diff consists of six additions only.
- [ ] PR 13/13 CI, 13/13 post-merge CI and local 8/8 must pass before closure.

## Suggested commands

```bash
uv run --locked ruff check src tests scripts
uv run --locked ruff format --check src tests scripts
uv run --locked python -m pytest -q \
  tests/security/test_oidc_c3_operator_evidence_intake_security.py \
  tests/security/test_oidc_c2_web_assurance_boundary_security.py \
  tests/security/test_oidc_authorization_boundary_security.py
uv run --locked python scripts/check_cern_web_operator_intake.py
uv run --locked python scripts/run_checks.py

git add -N \
  docs/adr/0033-cern-web-operator-evidence-intake.md \
  docs/security/cern-web-operator-evidence-guide.md \
  docs/security/cern-web-operator-intake-template.json \
  docs/development/phase1a2-5c3-acceptance.md \
  scripts/check_cern_web_operator_intake.py \
  tests/security/test_oidc_c3_operator_evidence_intake_security.py

git diff --check
git diff --stat
git status --short
```

Default CLI result: `RESULT=OPERATOR_REVIEW_REQUIRED` and all three gates
`NOT_SUPPLIED`. Required full gate result: `PASS=8 FAIL=0 SKIPPED=0`,
`Gate: ELIGIBLE FOR REVIEW`.

## Future operator review (not part of the implementation)

Resolve separate CERN web-client registration (G1), independently reviewed
positive MFA/LoA semantics and freshness (G6), and actual session/transaction
architecture and revocation policy (G7) **without** requesting secrets or
personal identity information in PRs or ordinary diagnostics. An opaque
reference is never an attestation or a release approval.
