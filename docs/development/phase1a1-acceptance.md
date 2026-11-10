# Phase 1A.1 acceptance: offline OIDC contracts

## Scope

This is the first identity foundation increment; **not** a login feature. It does not modify the frontend and it must not initiate a CERN request.

## Acceptance criteria

- [ ] The working branch is `feat/identity-foundation-1a1` and the patch applies cleanly to the accepted `main` commit `d961e97`.
- [ ] No new dependency, token, credential or network request was introduced.
- [ ] PKCE S256 matches the RFC 7636 known test vector.
- [ ] Tests reject unsafe URI schemes, callback correlation mismatch, expiry and replay.
- [ ] Concurrent redemption permits exactly one success.
- [ ] Authorization codes remain unverified and are not represented as authenticated users.
- [ ] `/api/v1/identity/status` reports CERN SSO unavailable, with security headers and no credentials.
- [ ] All prior domain, API, architecture, security, and frontend tests pass.
- [ ] Ruff and mypy pass; TypeScript type-checking and production build pass.
- [ ] Coverage remains at least 85% with branch measurement.
- [ ] No test is skipped and no relevant unexpected warning is hidden.
- [ ] A full diagnostic ZIP is reviewed before commit, push, PR or merge.
- [ ] Remote GitHub Actions checks (9 backend + 2 frontend + 2 aggregate) pass before merging.

## Local validation

```bash
cd ~/Desktop/atlas-scientific-code-assistant
uv run pytest -q tests/unit/test_identity.py tests/security/test_oidc_flow.py tests/contract/test_identity_api.py
uv run python scripts/run_checks.py
git diff --check
git status --short
```

## HTTP smoke test without starting Uvicorn

```bash
uv run python - <<'PY'
from fastapi.testclient import TestClient
from asca.api.main import create_app

with TestClient(create_app()) as client:
    response = client.get('/api/v1/identity/status')
    assert response.status_code == 200
    assert response.json()['authentication_enabled'] is False
    assert response.headers['cache-control'] == 'no-store'
    print('PASS: Identity endpoint is read-only and CERN login is disabled')
PY
```

## Required artifact to share for review

`diagnostics/phase0-diagnostics.zip` (the existing collector name, retained for regression compatibility).

No real CERN password, authorization code, token, cookies or `.env` file should ever be attached.
