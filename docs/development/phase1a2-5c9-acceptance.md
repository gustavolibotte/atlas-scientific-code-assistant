# Phase 1A.2.5C9 — Opt-in CERN web role and assurance observation

## Scope

- Add an **opt-in** `--observe-claims` mode to the *unmounted*, loopback-only C8 real CERN diagnostic.
- Observe the exact `asca-developer` application role for the fixed `asca-web-dev` client using the **same cryptographically checked ID Token** and one JWKS retrieval; never request a second authorization code or token response.
- Report only categorical role status and presence/absence of `acr`, `amr`, `auth_time`.
- No `acr` value, `amr` value, `auth_time` timestamp, identity, subject, token, code, state, nonce, group, role lists, or secret in output, logs or tests.
- Always report `MFA_PROOF=INDETERMINATE`, `LOA_PROOF=INDETERMINATE`, `AUTH_FRESHNESS=INDETERMINATE`, and `ROLE_AUTHORIZATION=DISABLED`.
- Treat `cern_roles_missing_mfa` and `cern_roles_missing_loa` as denial hints only. Presence of `asca-developer` is **not** a grant or independent provider attestation.
- Existing C8 **default** mode and status endpoint remain unchanged; C7 stays independent.
- No production ASCA API routes, sessions, dependencies, permissions, configuration, frontend or delegated-resource access change.

## Local quality gates

- [ ] Begin from clean `main` at `0f6adf042f579bb2cc097db2af3aa6bbf893ed5c`.
- [ ] Installer dry-run verifies the C8 Git blob, branch, checksums, and exactly one modification plus three additions.
- [ ] All 29 C8 and 32 C9 focused tests pass with **direct** `pytest` invocation.
- [ ] Ruff checks **including `prototypes`**, Ruff formatting, mypy and all 8 project quality gates pass.
- [ ] Examine `git diff --check`, `git diff --stat`, and the exact staged diff; confirm the only modified file is the isolated C8 prototype.
- [ ] Do not put Client Secret, callback URLs, claims or identity data in commits, screenshots, logs or PR descriptions.
- [ ] First test the new mode with **synthetic tests**. Only after review, run one opt-in real CERN SSO diagnostic. No real live authentication runs in CI.
- [ ] Require 13/13 PR checks, 13/13 post-merge checks, and 8/8 local checks before closing C9.

## Stop conditions

Even after a signed ID Token yields `ROLE_STATUS=CLAIMED` and `ACR_CLAIM=PRESENT`, the output is non-authoritative. CERN MFA/LoA semantics, freshness, application permission and distributed server-side session requirements remain unverified. Do not mark G1/G5/G6/G7 complete or enable login, ASCA authorization, chATLAS, GitLab, or protected tools.
