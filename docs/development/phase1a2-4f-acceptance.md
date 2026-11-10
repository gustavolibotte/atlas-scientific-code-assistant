# Phase 1A.2.4F acceptance: isolated CERN OIDC verification orchestration

## Scope

Compose the pinned HTTPS JWKS fetcher, strict JWKS parser, public-key construction/JWS signature verification and OIDC claims checks in order. Do not mount this service, accept key material directly from callers, create principals or sessions, access real CERN endpoints in tests, or modify existing dependencies.

## Acceptance checklist

- [ ] Start from clean `main` at reviewed PR #14 squash merge `cf936fd`, after 13/13 post-merge CI and 8/8 local quality gates.
- [ ] Use branch `feat/oidc-trusted-verification-orchestration-1a2-4f`, add only six source/test/documentation files, and preserve `pyproject.toml` and `uv.lock`.
- [ ] Keep orchestration in infrastructure to preserve the architecture guard; domain contains only an explicitly non-authenticating result and sanitized errors.
- [ ] Preflight pinned CERN issuer, exact JWKS URL and reviewed metadata endpoint/capabilities; reject invalid client/nonce/time policy before issuing a request.
- [ ] Fetch keys only through the pinned HTTPS transport; reject response types or source URLs that violate policy. Never accept a JWT `jku`/`x5u`, external JWKS object or prevalidated JWS/claims from the caller.
- [ ] Parse fetched bytes; verify a real JWS signature under one selected public key; check strict issuer, `aud`, `azp`, nonce, expiration and temporal policy, without promoting identity.
- [ ] Check both success and failures for RS256, PS256 and ES256 with synthetic ephemeral keys and fake HTTP responses. Verify network request count and absence of credentials.
- [ ] Fail closed on malformed JWKS, modified JWS headers/payloads, wrong signing keys, wrong audience/nonce, invalid signed claims, malicious metadata, unavailable HTTPS responses and forged intermediate objects.
- [ ] Use zero actual CERN HTTP requests, production authentication routes, new dependencies, sessions, permissions or access-token persistence.
- [ ] Run all focused tests and the complete project quality suite. `uv run --locked python scripts/run_checks.py` must show 8 PASS, 0 FAIL, 0 SKIPPED with backend branch coverage >=85%.
- [ ] Verify diagnostics, `git diff --check`, `git diff --stat`, `git status --short` and the six changed files prior to commit/push.
- [ ] Review the remote patch and require all 13 PR and post-merge GitHub Actions jobs before declaring phase complete.

## Commands

```bash
uv run --locked ruff check --select I --fix src/asca/domain/oidc_verification.py src/asca/infrastructure/oidc_verification.py tests/unit/test_oidc_verification.py tests/security/test_oidc_verification_security.py
uv run --locked ruff format src/asca/domain/oidc_verification.py src/asca/infrastructure/oidc_verification.py tests/unit/test_oidc_verification.py tests/security/test_oidc_verification_security.py
uv run --locked ruff check src tests scripts
uv run --locked pytest -q tests/unit/test_oidc_verification.py tests/security/test_oidc_verification_security.py
uv run --locked python scripts/run_checks.py
git diff --check
git diff --stat
git status --short
```

## Security notice

Passing all checks means **only** that the supplied token is mathematically valid under the keys returned by the *configured* fetcher and that its claims satisfy the supplied policy. Test injections are not provenance proofs. Do not use this result to log in a CERN user, assert CERN/ATLAS membership, authorize restricted resources, or create sessions. Do not include real CERN credentials, JWTs, cookies, client secrets or `.env` files in tests or diagnostics.
