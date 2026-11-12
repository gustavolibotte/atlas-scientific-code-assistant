# C8 — Isolated CERN Web OIDC Diagnostic

This is a **single-process localhost-only diagnostic**. It uses a real CERN OIDC
code exchange with PKCE and the repository's existing verification pipeline,
but **does not create an ASCA identity, application session, role permission, or
chATLAS/GitLab access**. It is intentionally separate from the C7 mock lab and
from `src/asca/`. No ASCA API route imports this prototype.

## CERN registration (already performed separately by the operator)

- CERN Applications Portal application: `asca-web-dev` (not the old native client)
- OIDC: Confidential Client, Authorization Code + PKCE S256
- Exact callback: `https://localhost:8443/oidc/callback`
- Base URL: `https://localhost:8443/`
- The `asca-developer` role may be configured and group-scoped in CERN, but
  **this diagnostic does not use that role for authorization**.
- Obtain the **OIDC Client ID** from the SSO credential view. It may differ from
  the application identifier. NEVER share the Client Secret, token, code or
  complete callback URL in messages, issue comments, screenshots or logs.

## Setup on the developer Mac

All commands below are run from the repository root. Stop C7 on port 8443 first.

```bash
uv lock --check
uv sync --all-groups --locked

# Public CERN metadata check. Performs a pinned HTTPS discovery GET only.
uv run --locked python prototypes/cern_web_oidc_probe.py --preflight

# One-time interactive secret entry; no echo or command-line argument.
# Writes an owner-readable file under diagnostics/, which is Git-ignored.
uv run --locked python prototypes/cern_web_oidc_probe.py --init-secret

# Reuse the localhost TLS certificate from C7, if available.
# Otherwise: brew install mkcert; mkcert -install
# mkdir -p diagnostics/cern-mock-lab
# mkcert -cert-file diagnostics/cern-mock-lab/localhost.crt \
#   -key-file diagnostics/cern-mock-lab/localhost.key localhost

uv run --locked python prototypes/cern_web_oidc_probe.py --serve \
  --client-id '<actual-client-id-from-CERN-portal>' \
  --certfile diagnostics/cern-mock-lab/localhost.crt \
  --keyfile diagnostics/cern-mock-lab/localhost.key
```

Open `https://localhost:8443/`, and click **Start CERN SSO diagnostic**.
The browser redirects to the pinned CERN authorization endpoint. After login,
it returns to `/oidc/callback`. A successful callback displays only a fixed
non-authoritative message; no user identifier, claim, role, secret or token.
Refreshing the callback must be rejected. The read-only status endpoint is
`https://localhost:8443/probe/status`.

### Credentials and logs

The secret file is `diagnostics/cern-web-probe/client_secret`, created exclusively
by `--init-secret` with mode `0600`, and never committed. Do not paste its
contents into chat. To rotate it, **stop the server**, securely replace this
file using your institution's prescribed secret-management procedure and rerun
with the new secret. Avoid shell `export`, `.env`, CLI secret arguments or
logging HTTP URLs containing authorization codes. The server runs with
`access_log=False` and ignores forwarded headers.

Never run this diagnostic on a public network interface, behind a reverse proxy,
or with multiple workers. It uses only process-local state and is intended for
manual localhost tests. It has no production authority.

## Security stop conditions

The probe refuses non-HTTPS or non-local Host requests, stale/mismatched browser
state, reused authorization codes, malformed callback parameters, changed CERN
issuer/endpoints, disallowed token signatures, invalid claims and unsuccessful
code exchanges. It reuses the existing strict signature/JWKS/claims checks
rather than implementing cryptography anew. It uses `client_secret_basic` at
the CERN token endpoint and will not silently downgrade to a different client
authentication scheme. If this exchange fails, inspect only sanitized status
and provider documentation; do not print full token responses or client secrets.

A successful diagnostic does **not** establish G1 provider attestation, G5
resource authorization, positive G6 MFA/LoA proofs, or G7 hosted session
security. It never verifies the caller's right to ASCA tools. Actual login
requires a separately approved architecture and independent evidence review.

## Offline tests and CI reproduction

```bash
uv run --locked ruff check src tests scripts prototypes
uv run --locked ruff format --check src tests scripts prototypes
uv run --locked pytest -q tests/security/test_cern_web_oidc_probe_security.py
uv run --locked pytest -q --cov=asca --cov-branch --cov-report=term-missing --cov-fail-under=85
uv run --locked python scripts/run_checks.py
```

The tests use fake token exchange and fake verifier results **only within the
unmounted offline test harness**. They do not contact CERN or claim to attest
real identity. Do not supply actual tokens to test fixtures.
