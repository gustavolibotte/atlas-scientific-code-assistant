# Phase 1A.2.5C5 acceptance — offline authorization decision contract

C5 produces one ADR, one security review, one versioned JSON contract, one
stdlib offline checker and one adversarial test module, plus this checklist.
It does **not** add a real authorization engine.

## Acceptance criteria

- [ ] Clean `main` at `eae138af864557ba15cd648aeca3b54d9aafa16f`
      (PR #32) and feature branch
      `feat/cern-authorization-decision-contract-1a2-5c5`.
- [ ] Installer verifies checksums and adds **six files, zero modifications**.
- [ ] Exact eight stages cover all G1–G10 and require DENY on missing evidence.
- [ ] Three resource classes remain disabled and separated (ASCA/chATLAS/GitLab).
- [ ] Request and decision-envelope fields are only names, not live input data.
- [ ] No `ALLOW`, `APPROVED`, login, session, resource access, credential
      handling or production route is introduced.
- [ ] G1/G6/G7 C2/C3 snapshots remain blocked and C4 contains 20 DENY cases.
- [ ] CLI checks exact contract, bounds file size, rejects duplicate JSON keys,
      unknown/mutated fields, symlinks and nonregular files, and prints no input.
- [ ] Offline focused pytest and eight project quality gates pass with no skip.
- [ ] `git diff --check` passes; diff contains exactly six additions.
- [ ] PR and postmerge CI each pass 13/13; local postmerge gates pass 8/8.

## Focused commands

```bash
uv run --locked ruff check src tests scripts
uv run --locked ruff format --check src tests scripts
uv run --locked python -m pytest -q \
  tests/security/test_oidc_c5_authorization_contract_security.py \
  tests/security/test_oidc_c4_negative_policy_security.py \
  tests/security/test_oidc_c3_operator_evidence_intake_security.py \
  tests/security/test_oidc_c2_web_assurance_boundary_security.py \
  tests/security/test_oidc_authorization_boundary_security.py
uv run --locked python scripts/check_cern_web_authorization_contract.py
uv run --locked python scripts/check_cern_web_negative_policy.py
uv run --locked python scripts/run_checks.py
```

Expected checker result:

```text
MODE=OFFLINE_AUTHORIZATION_DECISION_CONTRACT
ASCA_LOGIN=DISABLED
ASCA_SESSION=DISABLED
ROLE_AUTHORIZATION=DISABLED
CHATLAS_ACCESS=DISABLED
CONTRACT_STAGES=8
RESOURCE_CLASSES=3
SECURITY_GATES=10
C4_NEGATIVE_CASES=20
G1=BLOCKED
G6=BLOCKED
G7=BLOCKED
RESULT=INDEPENDENT_REVIEW_REQUIRED_NO_GRANT
```

Full quality gate requirement: `PASS=8 FAIL=0 SKIPPED=0` and
`Gate: ELIGIBLE FOR REVIEW`.

## Stop condition

The checker has no runtime policy authority. Even a structurally valid contract
and all tests green do not establish a CERN web-client registration, trusted
MFA/LoA evidence, session design, live login or delegated permissions.
