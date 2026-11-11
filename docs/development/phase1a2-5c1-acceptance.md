# Phase 1A.2.5C1 acceptance: authorization trust-boundary specification

The purpose of C1 is to record the prerequisites for a future CERN-authenticated
ASCA application and strengthen the regression tests for the current disabled
boundary. **No grant or login feature is implemented in this increment.**

## Scope and acceptance checklist

- [ ] Start from clean `main` at `4e0e68fbbd85cf0c8841da88dd951fb48d904176`.
- [ ] Install exactly four new files; no existing production files change.
- [ ] ADR 0031 defines trust levels and mandatory deployment gates.
- [ ] Threat register differentiates actual observed evidence from future requirements.
- [ ] Regression tests confirm no authenticated API routes or delegated resource access.
- [ ] Regression tests demonstrate that public, forgeable diagnostic objects
      never confer application/session capabilities.
- [ ] The existing `/api/v1/identity/status` reports CERN authentication disabled.
- [ ] The system capability `cern_sso` remains `not_implemented`.
- [ ] No new dependencies, browser login, callback endpoints, sessions, token storage,
      frontend behavior, HTTP transport or chATLAS integration.
- [ ] Focused and full eight-gate suites pass, with no skipped gates.
- [ ] The final diff has four new files only and `git diff --check` is clean.
- [ ] GitHub PR CI and post-merge CI pass before closing C1.

## Local verification

```bash
uv run --locked python -m pytest -q \
  tests/security/test_oidc_authorization_boundary_security.py \
  tests/contract/test_identity_api.py \
  tests/security/test_oidc_native_role_observation_security.py

uv run --locked ruff check src tests scripts
uv run --locked ruff format --check src tests scripts
uv run --locked python scripts/run_checks.py

git add -N \
  docs/adr/0031-cern-oidc-authorization-trust-boundary.md \
  docs/security/cern-oidc-authorization-threat-model.md \
  docs/development/phase1a2-5c1-acceptance.md \
  tests/security/test_oidc_authorization_boundary_security.py

git diff --check
git diff --stat
git status --short
```

Expected gates: `PASS=8 FAIL=0 SKIPPED=0`, `Gate: ELIGIBLE FOR REVIEW`.

## Non-goals

Do not run a live CERN test in this phase. Do not configure CERN client secrets,
create sessions, propose production authorization from `claimed` status, or
merge without a review of the threat register.

## Next increment after C1 review

Resolve the web-client registration, assurance and session-design questions
before writing a production authorization policy. A later standalone offline
policy prototype may be introduced only with explicit non-authoritative types,
independent security tests and a new ADR.
