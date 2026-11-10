# Phase 1A.2.1 acceptance: CERN OIDC discovery

## Scope

**Only** provider configuration and public metadata discovery/validation. Not login, authorization, session creation, token exchange, JWT signature verification, JWKS download, or CERN application registration.

## Acceptance checklist

- [ ] Branch `feat/cern-oidc-discovery-1a2-1` is based on accepted `main` commit `7d0e798`.
- [ ] No existing ASCA functionality was overwritten or removed.
- [ ] Public CERN issuer and discovery URL are independent, pinned trust anchors.
- [ ] Validation rejects mismatched issuers, alternate origins, HTTP, redirects, bad JSON, missing S256 and unsupported signing algorithms.
- [ ] The default CLI runs offline; the optional `--live` mode is a single bounded public HTTPS request.
- [ ] Login and callback routes remain disabled; `cern_sso` remains `not_implemented`.
- [ ] No real client credentials, raw tokens, cookies or secret material appear in the patch or test output.
- [ ] New unit, security and contract tests pass without a network connection.
- [ ] `uv run python scripts/run_checks.py` passes all eight checks, no skips, coverage >= 85%.
- [ ] Any live discovery attempt is recorded with its result, not masked as success.
- [ ] User submits a diagnostic archive for review **before** commit, push or pull request.
- [ ] All 13 GitHub Actions jobs pass before merge and the protected `main` passes again after merge.

## Local verification

```bash
cd ~/Desktop/atlas-scientific-code-assistant
uv run pytest -q \
  tests/unit/test_oidc_discovery.py \
  tests/security/test_oidc_metadata_transport.py \
  tests/contract/test_oidc_probe_cli.py
uv run python scripts/run_checks.py
uv run python scripts/check_cern_oidc_discovery.py
# Optional: run once only if network access to CERN SSO is permitted/available.
uv run python scripts/check_cern_oidc_discovery.py --live

git diff --check
git status --short
```

## Diagnostics

Share `diagnostics/phase0-diagnostics.zip` (the established collector) and the sanitized output of the optional public `--live` probe. The diagnostic ZIP does not include a live network probe automatically.

A missing CERN Application Portal registration is **expected** at this stage. No client ID or secret is required to validate public discovery. An unsuccessful live probe is not permission to guess endpoints or fall back to an insecure method.
