# C7 — Isolated HTTPS OIDC BFF laboratory

**MOCK provider only.** This is a runnable browser demonstration of an OIDC
Authorization Code + PKCE S256 transaction. The mock IdP signs ephemeral RS256
ID Tokens; the BFF checks state, per-browser binding, nonce, signature, issuer,
audience and expiration. State, authorization tickets and codes are single-use.
It never authenticates a CERN account, logs a user in to ASCA, creates an
application session, or grants any protected action.

It is deliberately **not** under `src/asca`; do not mount it in the ASCA API,
deploy it, reuse the mock issuer, or insert real client secrets. Its in-process
mock backchannel and process-local stores are not production equivalents of
independent CERN TLS provenance or distributed storage.

## Local-only browser demonstration

From the repository root, with `uv sync --all-groups --locked` completed:

```bash
mkdir -p diagnostics/cern-mock-lab
chmod 700 diagnostics/cern-mock-lab
openssl req -x509 -newkey rsa:3072 -sha256 -nodes \
  -keyout diagnostics/cern-mock-lab/localhost.key \
  -out diagnostics/cern-mock-lab/localhost.crt -days 1 \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost'
chmod 600 diagnostics/cern-mock-lab/localhost.key
uv run --locked python prototypes/cern_web_bff_lab.py \
  --certfile diagnostics/cern-mock-lab/localhost.crt \
  --keyfile diagnostics/cern-mock-lab/localhost.key
```

Visit `https://localhost:8443/lab` on the same Mac. A self-signed certificate
will not be trusted by browsers by default. For a clean experience, install
and use a trusted **local-only** development certificate (e.g. `mkcert`) instead;
never accept a TLS warning for the real CERN SSO. The server listens on
`127.0.0.1` only; stop with Ctrl+C. Never enter CERN credentials into the mock
provider page; it does not ask for any.

## Tests

```bash
uv run --locked ruff format --check src tests scripts prototypes
uv run --locked ruff check src tests scripts prototypes
uv run --locked python -m pytest -q tests/security/test_cern_web_bff_lab_security.py
uv run --locked python scripts/run_checks.py
```

`run_checks.py` already checks the production repository. Its Ruff commands
currently include `src tests scripts`, so the new prototype receives explicit
additional Ruff checks above. The new test module is included in backend pytest.

## Next step outside the repository

Register a **separate** confidential OIDC web/BFF client in the CERN
Applications Portal, distinct from the existing native `asca-glibotte-dev`.
Choose the real HTTPS BFF hostname and exact callback before registering.
Do not register the lab's `https://localhost:8443` callback as a deployed web
application, and do not reuse the native public/loopback registration.

Record only non-sensitive answers: application identifier, client type,
allowed flow, token endpoint authentication method, redirect URI, scopes,
registered owner, and whether review of MFA/LoA role semantics is pending.
Never submit or commit the client secret or user tokens. A later standalone
implementation increment will test the actual CERN exchange only after the
independent G1/G6/G7 trust and deployment review.
