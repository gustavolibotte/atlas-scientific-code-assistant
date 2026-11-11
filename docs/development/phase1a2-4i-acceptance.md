# Phase 1A.2.4I acceptance: default-only isolated CERN native bootstrap

## Goal

Reduce inadvertent promotion of test-injected native OIDC transports and verifier objects by adding an unmounted, default-adapter composition root. Maintain a strictly non-authenticating status. Do not enable CERN login or modify current native/BFF implementations.

## Checklist

- [ ] Start with clean `main` at reviewed PR #17 squash merge `64c15388d5c11e97c550f4e1394520ade063805d`, after 13/13 CI and 8/8 local quality gates.
- [ ] Create branch `feat/oidc-native-default-bootstrap-1a2-4i`; add exactly six files and no dependencies, API routes, frontend changes or edits to existing files.
- [ ] Reconstruct an exact native-only registration and reject malformed, forged, BFF or mutated declarations.
- [ ] Accept no injected metadata, public JWKS, transport, verifier, signed token, PKCE value, clock or session in the new bootstrap API.
- [ ] Retrieve the pinned public CERN discovery URL with system CA and hostname validation, without environment proxies or redirects; use the reviewed strict discovery parser.
- [ ] Recheck issuer, exact authorization/token/JWKS endpoint strings, asymmetric signing algorithms and S256/code-flow capabilities.
- [ ] Construct the existing native service with default adapters and check concrete types; do not mistake these structural checks for provenance proof.
- [ ] Preserve the explicit `not_implemented` login state and absence of identities, sessions and permissions.
- [ ] Test malicious provider metadata, operator configuration, validation exceptions, proxy settings, unexpected objects, source mutation and adapter substitution using synthetic offline fixtures.
- [ ] Run focused tests and the complete eight quality gates; inspect coverage, diagnostics, git diff and resulting file list before committing.
- [ ] Require 13/13 PR GitHub Actions jobs plus review before merge, and 13/13 post-merge jobs plus 8/8 local gates before closing the phase.

## Validation commands

```bash
uv run --locked ruff check --select I --fix src/asca/domain/oidc_native_bootstrap.py src/asca/infrastructure/oidc_native_bootstrap.py tests/unit/test_oidc_native_bootstrap.py tests/security/test_oidc_native_bootstrap_security.py
uv run --locked ruff format src/asca/domain/oidc_native_bootstrap.py src/asca/infrastructure/oidc_native_bootstrap.py tests/unit/test_oidc_native_bootstrap.py tests/security/test_oidc_native_bootstrap_security.py
uv run --locked ruff check src tests scripts
uv run --locked pytest -q tests/unit/test_oidc_native_bootstrap.py tests/security/test_oidc_native_bootstrap_security.py
uv run --locked python scripts/run_checks.py
git diff --check
git diff --stat
git status --short
```

## Acceptance evidence

The isolated Linux/Python 3.13 reconstructed-component regression passed 96 new tests and 1,385 available historical tests (total includes the new tests). Both new modules reached 100% statement and branch coverage under the isolated fixtures. The reconstructed environment includes a current-version fix to an older archived preflight module, not a change to the candidate or repository. Ruff, mypy, complete repository tests and frontend gates were not available in the isolated environment and **must** pass on the developer Mac before PR creation.

**Not production-ready:** Official registration attestation, a secured native callback listener, multiworker persistence, tests against the live CERN provider and a non-forgeable authenticated-identity trust boundary are not implemented. CERN SSO stays disabled.
