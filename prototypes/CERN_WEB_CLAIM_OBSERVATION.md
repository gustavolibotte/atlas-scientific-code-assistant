# C9 — CERN web role and assurance-claim observation

This phase **extends** the isolated C8 HTTPS diagnostic using an opt-in
`--observe-claims` switch. It is not an authentication or authorization feature.
All ASCA production login, sessions, app permissions and delegated resource access
remain disabled.

## Purpose

A real CERN OIDC transaction has already been shown to pass token signature,
issuer, audience, nonce and expiry checks (C8). C9 inspects the **same checked ID
Token** for one strictly scoped web-application role and the **presence only** of
OIDC assurance-related fields. It does not fetch another token or JWKS, does not
persist an ID Token and never prints raw claims or personal data.

For the selected `asca-web-dev` client, `ROLE_STATUS` is one of:

- `CLAIMED`, `ABSENT`
- `MFA_REQUIRED`, `LOA_REQUIRED`, `MFA_AND_LOA_REQUIRED`

The role inspector requires an exact `resource_access["asca-web-dev"].roles`
entry. Realm roles, roles for the old `asca-glibotte-dev` client, group membership,
usernames and email addresses never substitute for that claim. CERN role-denial
indicators are interpreted only as missing assurances, not proof that an MFA or
LoA requirement was fulfilled.

The observations `ACR_CLAIM`, `AMR_CLAIM`, `AUTH_TIME_CLAIM` use only the fixed
labels `PRESENT`, `ABSENT` (or `EMPTY` for an empty `amr` array). The underlying
values are not emitted. No provider-specific `acr`/`amr` meaning is assumed, and
an `auth_time` without a policy-specific maximum age is **not** freshness proof.

Every success prints:

```text
MFA_PROOF=INDETERMINATE
LOA_PROOF=INDETERMINATE
AUTH_FRESHNESS=INDETERMINATE
ROLE_AUTHORIZATION=DISABLED
```

The `CernOidcVerificationPipeline._verified_payload` internal API is used **only
inside this local prototype**. It is not a stable or approved production
interface. Production trust boundaries require a separate reviewed design.

## Local operator workflow

Stop the C8 process on port 8443 before starting C9. Reuse the previously
registered client ID, localhost TLS certificate and ignored owner-only secret
file. Do not initialize the secret again if one is already stored.

Run quality gates **before** any real CERN login:

```bash
uv run --locked ruff check src tests scripts prototypes
uv run --locked ruff format --check src tests scripts prototypes
uv run --locked pytest -q tests/security/test_cern_web_oidc_probe_security.py \
  tests/security/test_cern_web_claim_observation_security.py
uv run --locked python scripts/run_checks.py
```

Then start the opt-in probe:

```bash
uv run --locked python prototypes/cern_web_oidc_probe.py --serve \
  --observe-claims --client-id asca-web-dev \
  --certfile diagnostics/cern-mock-lab/localhost.crt \
  --keyfile diagnostics/cern-mock-lab/localhost.key
```

Open `https://localhost:8443/`, select **Start CERN SSO diagnostic**, finish
CERN SSO, and transcribe **only** the fixed categorical output. A refresh of the
same callback must be rejected. The status endpoint remains unchanged.

Never publish the full callback URL, bearer tokens, `id_token`, the Client
Secret, login errors, claim values, or identity information in diagnostics,
commits, screenshots, issues or prompts. `--observe-claims` cannot be used with
`--preflight` or `--init-secret`.

## Limitations and security prerequisites

- The role is an observed claim in a token from this local transaction, not a
  durable ASCA application entitlement or a provider attestation.
- Keycloak commonly maps client roles into an access token; not all provider
  configurations necessarily include them in an ID Token. `ABSENT` therefore
  does not establish that CERN group membership is missing.
- `acr`, `amr` and `auth_time` may not be returned and have provider-specific
  interpretations. Their presence **never** proves MFA/LoA or freshness here.
- This remains single-process `127.0.0.1` only. Pending authorization state is
  not distributed; no server-managed session, CSRF permission or revocation
  system is implemented.
- Do not relax CSP, allow proxy headers, print live credentials or mount the
  prototype in `src/asca/api/`.

References:

- CERN SSO application/role configuration: https://auth.docs.cern.ch/applications/application-configuration/
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
- Keycloak role mappings: https://www.keycloak.org/docs/latest/server_admin/
- ASCA ADRs 0028–0036.
