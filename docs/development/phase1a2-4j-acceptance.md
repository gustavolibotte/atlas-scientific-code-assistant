# Phase 1A.2.4J acceptance: native loopback callback request policy

## Scope

Add an unmounted and strictly non-authenticating parser for a future native-loopback HTTP callback. This parser does not create sockets, authenticate users, consume stored states or call CERN. It must not change existing API routes, login capability, native exchange, dependencies or previous tests.

## Acceptance checklist

- [ ] Start from reviewed `main` after PR #18 at `9d212819269eddd8d9737080d0f2d96443973b05`, with 13/13 post-merge CI and 8/8 local gates.
- [ ] Use `feat/oidc-native-loopback-callback-policy-1a2-4j` and add only six domain/infrastructure/test/documentation files.
- [ ] Keep the parser under infrastructure; the domain has only forgeable, non-authoritative data contracts and a sanitized exception.
- [ ] Require native registration, exact 127.0.0.1 / ::1 binding, explicit port, exact path and exactly one Host header; reject alternate hosts, proxy-provided authority and mismatched socket addresses.
- [ ] Enforce HTTP/1.1 GET, request-target bounds, no body, valid header characters, no forbidden headers and strict query parsing with no duplicate, unknown or ambiguous OAuth fields.
- [ ] Validate generated state shape, a bounded authorization code or denial identifier, and exact optional CERN `iss`; never use callback parameters as a token endpoint, key URL or browser binding.
- [ ] Preserve error callbacks as untrusted errors, with no login/identity/session/permission grant. Do not assert that parsing consumes a pending attempt or establishes browser origin.
- [ ] Cover IPv4/IPv6, percent-encoded query, header confusion, route mismatch, forgery, malformed inputs and secret non-disclosure in deterministic offline tests.
- [ ] Execute Ruff, mypy, focused pytest, complete `scripts/run_checks.py`, inspect diagnostics ZIP and `git diff --check` before commit.
- [ ] Require 13/13 PR CI and post-merge CI and repeat local 8/8 after merge before formal acceptance.

## Commands

```bash
uv run --locked ruff check --select I --fix src/asca/domain/oidc_native_callback.py src/asca/infrastructure/oidc_native_callback.py tests/unit/test_oidc_native_callback.py tests/security/test_oidc_native_callback_security.py
uv run --locked ruff format src/asca/domain/oidc_native_callback.py src/asca/infrastructure/oidc_native_callback.py tests/unit/test_oidc_native_callback.py tests/security/test_oidc_native_callback_security.py
uv run --locked ruff check src tests scripts
uv run --locked pytest -q tests/unit/test_oidc_native_callback.py tests/security/test_oidc_native_callback_security.py
uv run --locked python scripts/run_checks.py
git diff --check
git diff --stat
git status --short
```

## Security notice

The request envelope is intentionally forgeable. Peer/local IP fields are trustworthy only when supplied by a correctly implemented OS-socket-based listener (not built here). A validated callback is **not** a verified identity, a state-consumption receipt, an authorization grant, or a usable CERN login result. The future native listener must acquire binding from protected local host context, atomically consume state, handle provider denial and close its socket. No actual CERN credentials, tokens, secrets or live CERN requests are permitted in the tests.
