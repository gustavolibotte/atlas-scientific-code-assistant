# Phase 1A.2.4C acceptance: offline cryptographic public-key construction

## Scope

Construct RSA and P-256 public-key objects from already parsed but unverified-provenance CERN JWKS declarations. Do not fetch keys, parse JWT headers, verify signatures, verify claims, create authenticated principals or sessions, or enable CERN SSO.

## Acceptance criteria

- [ ] Start from clean `main` at the PR #11 squash merge `7b07c60`, with 13/13 GitHub Actions jobs and 8/8 local quality gates passing.
- [ ] Work in `feat/oidc-crypto-public-key-construction-1a2-4c`. Create only six new source/test/documentation files, amend `pyproject.toml` only to add the reviewed `cryptography` constraint, and resolve/update `uv.lock`.
- [ ] Construct only approved RSA for `RS256`/`PS256`, and EC P-256 for `ES256`. Reuse exact `kid`/algorithm selection and revalidate forged dataclass values.
- [ ] Reject even/undersized/oversized/noncanonical RSA integers and invalid exponents; rely on the cryptographic backend to construct public keys.
- [ ] Reject off-curve EC points and incorrect curves, coordinates, or cross-family fields.
- [ ] Do not claim that public-key construction establishes CERN key provenance, signature validation, OIDC identity, or session authorization.
- [ ] Synthetic public-only and entirely offline tests; no private keys, real CERN tokens, or network calls.
- [ ] `uv lock` updates the tracked lockfile. `uv sync --all-groups --locked` and `uv run --locked` succeed. Review the lockfile's changed packages.
- [ ] Focused tests pass, and full `uv run --locked python scripts/run_checks.py` yields 8 PASS, 0 FAIL, 0 SKIPPED with >=85% branch coverage.
- [ ] `git diff --check`, diff stat, and full diagnostic ZIP reviewed before any commit or push.
- [ ] Require 13/13 GitHub Actions jobs on PR and post-merge `main`.

## Local commands

```bash
uv lock
uv sync --all-groups --locked
uv run --locked ruff format src/asca/infrastructure/oidc_crypto_key.py src/asca/domain/oidc_crypto_key.py tests/unit/test_oidc_crypto_key.py tests/security/test_oidc_crypto_key_security.py
uv run --locked ruff check src tests scripts
uv run --locked ruff format --check src tests scripts
uv run --locked mypy src
uv run --locked pytest -q tests/unit/test_oidc_crypto_key.py tests/security/test_oidc_crypto_key_security.py
uv run --locked python scripts/run_checks.py
git diff --check
git diff --stat
git status --short
```

## Security notice

No real CERN client data, access tokens, authorization codes, private keys, or `.env` files should be uploaded to GitHub or included in test fixtures. A validated public-key object is only a cryptographic primitive, not a trusted signing key for an authenticated user.
