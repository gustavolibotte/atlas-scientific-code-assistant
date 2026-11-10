# Phase 1A.2.4D acceptance: offline JWS signature verification

## Scope

Introduce only an offline JWS signature checker and explicitly non-authenticating result contract. Continue to use existing token parser, strict JWKS declarations and public-key builder without modifying them. There are no production login routes, JWKS fetch orchestration, OIDC claims validation, token storage, sessions or dependency changes.

## Acceptance criteria

- [ ] Start from clean `main` at the reviewed PR #12 squash merge `e1c7110`, with post-merge 13/13 GitHub Actions jobs passing and local 8/8 quality checks.
- [ ] Work in branch `feat/oidc-jws-signature-verification-1a2-4d`. Add exactly six new files; do not overwrite existing code or modify `pyproject.toml` / `uv.lock`.
- [ ] Require three nonempty canonical base64url JWS segments with bounded lengths; reject malformed, padded, detached, oversized or noncanonical input.
- [ ] Strictly parse the protected JOSE header, rejecting duplicate members, malicious key references and unknown header fields. Only `alg`, `kid`, and optional `typ=JWT` are approved.
- [ ] Prevent algorithm confusion: support only exact `RS256`, `PS256`, `ES256`, bound to an exact approved `kid`/algorithm key via the existing public-key constructor.
- [ ] Verify RSA PKCS#1 v1.5 SHA-256 and RSA-PSS SHA-256 MGF1 with fixed 32-byte salt, and P-256 ECDSA SHA-256 with 64-byte raw JWS signatures.
- [ ] Reject invalid ECDSA R/S ranges, DER-encoded JWS signatures, signature tampering, payload tampering, key substitution and wrong PSS salt length.
- [ ] Preserve untrusted-provenance and unverified OIDC claims after cryptographic verification. No principal, session, role or authorization is created.
- [ ] Only ephemeral synthetic test signing keys in memory. No real CERN endpoints, tokens, cookies, credentials, `.env` files or persisted private keys.
- [ ] Run 107 focused tests and the full quality suite. `uv run --locked python scripts/run_checks.py` must produce 8 PASS / 0 FAIL / 0 SKIPPED with backend branch coverage >=85%.
- [ ] Review local diagnostic ZIP and `git diff --check`, `git diff --stat`, `git status --short` before commit or push.
- [ ] Require 13/13 GitHub Actions jobs for the PR and again on `main` after merge.

## Local commands

```bash
uv run --locked ruff format src/asca/domain/oidc_jws.py src/asca/infrastructure/oidc_jws.py tests/unit/test_oidc_jws.py tests/security/test_oidc_jws_security.py
uv run --locked ruff check src tests scripts
uv run --locked ruff format --check src tests scripts
uv run --locked mypy src
uv run --locked pytest -q tests/unit/test_oidc_jws.py tests/security/test_oidc_jws_security.py
uv run --locked python scripts/run_checks.py
git diff --check
git diff --stat
git status --short
```

## Security notice

Never test against live CERN credentials or use these JWS checks to authenticate a user. Cryptographic validity under a supplied public key does not prove that CERN supplied that key. A separate trusted-fetch orchestration and complete ID-token claims validation are mandatory before login is considered.
