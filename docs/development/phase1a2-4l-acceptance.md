# Phase 1A.2.4L acceptance: isolated native loopback listener security

## Objective

Add an **unmounted** local TCP listener, with OS-selected loopback port and single callback receipt, suitable only for a future explicitly reviewed native OIDC host. Do not enable CERN SSO or modify existing ASCA routes, identity boundaries, dependencies or the native callback/lifecycle modules.

## Acceptance criteria

- [ ] Base exactly on the reviewed PR #20 `main` merge commit `b1c31b7300e4d67e1ee76b465843f22c4c21ccd2` and branch `feat/oidc-native-loopback-listener-1a2-4l`.
- [ ] Add exactly six files: two source modules, two new test modules, ADR 0023 and this document; no prior file modifications or lockfile changes.
- [ ] Bind an actual TCP socket only to literal `127.0.0.1` or `::1` and kernel-selected ephemeral port; reject wildcard, DNS names, remote addresses and explicit user-selected port.
- [ ] Use `IPV6_V6ONLY` for IPv6; reconstruct native `OidcClientRegistration` with the actual port, then validate with the existing HTTP callback policy.
- [ ] Parse raw HTTP/1.1 requests with preserved header duplication; reject unsupported versions, methods, hosts, forwarding and forbidden headers, malformed/ambiguous OAuth fields, request bodies and invalid length/encoding.
- [ ] Populate local/peer endpoint fields from accepted socket OS APIs, not from untrusted HTTP headers or query arguments.
- [ ] Enforce read size, total and per-connection deadlines, accepted connection budget, single receiver and deterministic shutdown on callback receipt, exhaustion, timeout and explicit close.
- [ ] Send only secret-free fixed HTTP `202`/`400` responses with no content or redirects; never interpret HTTP `202` as an authenticated identity or confirmed transaction state.
- [ ] Demonstrate callback parsing via real local sockets with success and denial, and subsequent state/PKCE correlation by the existing `CernNativeCallbackLifecycle`, entirely using synthetic test adapters.
- [ ] Run targeted tests and complete `scripts/run_checks.py` in the official Mac environment; inspect coverage, diagnostics, Ruff, mypy, frontend, and exact six-path Git diff **before** commit.
- [ ] Review the PR and require all 13 PR CI jobs before merge, all 13 post-merge jobs and final local 8/8 before phase closure.

## Local commands

```bash
uv run --locked ruff check --select I --fix src/asca/domain/oidc_native_listener.py src/asca/infrastructure/oidc_native_listener.py tests/unit/test_oidc_native_listener.py tests/security/test_oidc_native_listener_security.py
uv run --locked ruff format src/asca/domain/oidc_native_listener.py src/asca/infrastructure/oidc_native_listener.py tests/unit/test_oidc_native_listener.py tests/security/test_oidc_native_listener_security.py
uv run --locked ruff check src tests scripts
uv run --locked pytest -q tests/unit/test_oidc_native_listener.py tests/security/test_oidc_native_listener_security.py
uv run --locked python -m pytest -q tests/unit/test_oidc_native_listener.py tests/security/test_oidc_native_listener_security.py
uv run --locked python scripts/run_checks.py
git add -N src/asca/domain/oidc_native_listener.py src/asca/infrastructure/oidc_native_listener.py tests/unit/test_oidc_native_listener.py tests/security/test_oidc_native_listener_security.py docs/adr/0023-ephemeral-native-loopback-http-listener.md docs/development/phase1a2-4l-acceptance.md
git diff --check
git diff --stat
git status --short
```

## Limitations of isolated acceptance evidence

The development container includes the available prior OIDC source and tests but not the complete ASCA repository or frontend. Local real-loopback tests and partial regression are informative; **the official Mac and GitHub quality gates are mandatory**. Live CERN credentials, live OIDC requests and an actual production login are strictly outside scope.
