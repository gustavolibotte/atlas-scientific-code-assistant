# Phase 1A.2.4M acceptance: native host orchestration and transaction binding

## Objective

Compose the existing OS loopback listener, the native OIDC code exchange and the atomic callback lifecycle into **one unmounted, single-use, synthetic/offline-tested native host transaction**, without exposing the protected browser binding or introducing authenticated identity.

## Acceptance criteria

- [ ] Start from clean reviewed PR #21 merge commit `4dfe888bc12e502156c70baf111407d13027b6eb`; create branch `feat/oidc-native-host-transaction-1a2-4m`.
- [ ] Add exactly six files: two new source modules, two new test modules, ADR 0024 and this document. Do not modify old code/tests, frontend, API routes, dependencies, or `uv.lock`.
- [ ] Create listener first and configure native exchange from the actual OS-selected callback port and registration. Reject initial configuration mismatches and close the socket on partial construction failure.
- [ ] Require explicitly supplied testing metadata, transport and verifier. Reject default HTTPS token/verifier adapter instances; do not contact CERN during tests.
- [ ] Return only the authorization URL/redirect URI from `begin()`. Never return the protected browser binding, PKCE verifier, token, grant or principal. Check endpoint and exact query/redirect values before returning.
- [ ] `complete()` must not accept a caller-supplied HTTP envelope, state, binding, verifier or token. Use the owned listener for OS socket metadata and the original lifecycle for atomic correlation.
- [ ] Close the listener before any token request, and return only an untrusted token-check descriptor or a denial marker; no authenticated session/permissions.
- [ ] Ensure one shot, replay rejection, cancellation-driven atomic pending attempt revocation, expiry and invalid-state terminal refusal, including races with `close()` and concurrent `complete()`.
- [ ] Test actual local-loopback IPv4 and optional IPv6, malicious HTTP, tampered start URLs, forged registration, failures of socket/transport/verifier, and safe exception text, with **zero CERN traffic**.
- [ ] Run both focused pytest invocations, Ruff, format, mypy, `scripts/run_checks.py`, diagnostics/coverage, and exact six-path diff before commit or push. Require `PASS=8 FAIL=0 SKIPPED=0`.
- [ ] Before merging, review the GitHub PR patch and 13/13 matrix+gate CI. After merging, require 13/13 post-merge CI plus 8/8 local Mac gates.

## Local commands

```bash
uv run --locked ruff check --select I --fix src/asca/domain/oidc_native_host.py src/asca/infrastructure/oidc_native_host.py tests/unit/test_oidc_native_host.py tests/security/test_oidc_native_host_security.py
uv run --locked ruff format src/asca/domain/oidc_native_host.py src/asca/infrastructure/oidc_native_host.py tests/unit/test_oidc_native_host.py tests/security/test_oidc_native_host_security.py
uv run --locked ruff check src tests scripts
uv run --locked pytest -q tests/unit/test_oidc_native_host.py tests/security/test_oidc_native_host_security.py
uv run --locked python -m pytest -q tests/unit/test_oidc_native_host.py tests/security/test_oidc_native_host_security.py
uv run --locked python scripts/run_checks.py
git add -N src/asca/domain/oidc_native_host.py src/asca/infrastructure/oidc_native_host.py tests/unit/test_oidc_native_host.py tests/security/test_oidc_native_host_security.py docs/adr/0024-isolated-native-oidc-host-transaction-binding.md docs/development/phase1a2-4m-acceptance.md
git diff --check
git diff --stat
git status --short
```

## Isolated preliminary evidence and limitations

The development environment reconstructs the available previous OIDC backend source and tests, **not** the complete Mac repository or frontend. The initial isolated run passed **1,845 Python tests**, including **89 new tests** and **100% statement/branch coverage in both new modules**. The official Mac and remote CI results remain mandatory before acceptance.

The host is an unmounted, non-authenticating, explicit-adapter research component. A future production login must have its own independently reviewed trusted identity/session and registered CERN-client boundary.
