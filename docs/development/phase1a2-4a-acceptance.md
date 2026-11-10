# Phase 1A.2.4A acceptance: offline CERN JWKS public-key declaration validation

## Scope

Introduce only a strict parser and exact selector for *unverified-provenance* asymmetric signing JWK declarations. No JWKS HTTP fetch, JWT/JWS signature verification, public-key construction, provider login, ID-token claims validation, authenticated principal, or session. CERN SSO remains `not_implemented`.

## Acceptance criteria

- [ ] Begin from clean `main` at the PR #9 merge `438f59c`, with local 8/8 quality gates and GitHub Actions 13/13 post-merge CI.
- [ ] Work on `feat/oidc-jwks-trust-foundation-1a2-4a` and add the six candidate files without overwriting existing files or dependencies.
- [ ] Require exact CERN issuer and JWKS URI, and locally approved asymmetric algorithms. Metadata objects alone are not proof of trusted discovery.
- [ ] Bound JSON to 262,144 bytes, 64 keys, strict UTF-8 and unique members; require unique, safe `kid` values.
- [ ] Reject private/symmetric JWK parameters, embedded remote references, incompatible key operations and algorithm/type confusion.
- [ ] Require canonical public parameters, RSA modulus of at least 2,048 bits and ES256 P-256 coordinate lengths; no claim of cryptographic key validity.
- [ ] Ignore non-signing, nonapproved and unknown noncritical extensions without using them as identity or authorization.
- [ ] Select only exact `kid` and approved, matching `alg`; do not infer keys from token-provided URLs or embedded JWK objects.
- [ ] Test adversarial examples entirely offline, with synthetic public parameters; no CERN secrets or network calls.
- [ ] `uv run python scripts/run_checks.py`: 8 PASS, 0 FAIL, 0 SKIPPED, backend branch coverage >=85%.
- [ ] Review focused tests, full local diagnostic ZIP and diff before commit/push/PR.
- [ ] Require 13 GitHub Actions jobs on the PR and again on `main` after merge.

## Local commands

```bash
uv run ruff format \
  src/asca/domain/oidc_jwks.py src/asca/application/oidc_jwks.py \
  tests/unit/test_oidc_jwks.py tests/security/test_oidc_jwks_security.py
uv run ruff check src tests scripts
uv run pytest -q tests/unit/test_oidc_jwks.py tests/security/test_oidc_jwks_security.py
uv run python scripts/run_checks.py
git diff --check
git diff --stat
git status --short
```

## Prohibited actions

Do not test against live CERN JWKS or tokens in this increment, do not add a CERN login route, and do not send authorization codes, ID tokens, client secrets or `.env` files to diagnostics or GitHub. The JWKS fixtures contain synthetic *public* parameters only.
