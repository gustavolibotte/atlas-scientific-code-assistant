# Phase 1A.2.5C2 acceptance — CERN web-client and assurance review

## Scope

Review design and source-backed provider requirements for G1/G6/G7 and
associated security gates. Add only four documentation/data artifacts and one
offline security test file. **No runtime modification, provider registration,
login, session, authorization grant, real CERN request or chATLAS access.**

## Acceptance checklist

- [ ] Base `main` commit `fc641fbd12b5cf364ad9f63a142f81fa93818dc5`
      (PR #29), clean feature branch
      `feat/cern-oidc-web-assurance-review-1a2-5c2`.
- [ ] Guarded installer reports exactly five new files and no modifications.
- [ ] ADR 0032 separates CERN documentation, operator attestations and
      ASCA security design decisions; it does not imply an approved web client.
- [ ] Web registration documents the CERN public-client checkbox and
      client-credentials advanced option accurately, without enabling either.
- [ ] Reviewed role claim and missing-MFA/LoA evidence is never promoted to
      affirmative assurance without an approved CERN provider contract.
- [ ] Session requirements include secure cookie, CSRF, distributed single-use
      transaction, expiry, key rotation, role refresh and revocation.
- [ ] Machine-readable evidence register covers G1–G10, with no gates
      recorded as complete, and references to verifiable public documents.
- [ ] ASCA API continues reporting authentication not configured; no API
      login/callback or privileged resources are mounted.
- [ ] Focused offline tests and all eight quality gates pass with no skips.
- [ ] The complete diff contains exactly five additions, `git diff --check`
      is clean, and no credentials or personal claims are present.
- [ ] Before merge: 13 PR CI checks. After merge: 13 main CI checks plus
      local `uv lock --check`, `uv sync --all-groups --locked` and 8 gates.

## Focused validation

```bash
uv run --locked ruff check src tests scripts
uv run --locked ruff format --check src tests scripts
uv run --locked python -m pytest -q \
  tests/security/test_oidc_c2_web_assurance_boundary_security.py \
  tests/security/test_oidc_authorization_boundary_security.py \
  tests/contract/test_identity_api.py
uv run --locked python scripts/run_checks.py
```

Require `PASS=8 FAIL=0 SKIPPED=0` and `Gate: ELIGIBLE FOR REVIEW`.

## Later decision prerequisites

Operator-approved nonsecret record of a **separate** web client, authoritative
CERN assurance semantics, a reviewed web BFF threat model and a session
architecture decision. This increment does not approve these decisions or
propose a live login. Do not request client secrets or identity token dumps.
