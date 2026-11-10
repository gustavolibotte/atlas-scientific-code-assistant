# OIDC discovery: threat model and controls

## Security boundary

Only *public provider metadata* is retrieved. The metadata has no authority to grant a session or access to chATLAS, ATLAS material, or GitLab CERN. The retrieved data is checked against a policy compiled into the application code.

| Threat | Mitigation | Outstanding work |
| --- | --- | --- |
| SSRF via arbitrary URL | The only fetch URL is injected from the trusted policy; HTTP input cannot select URLs | Additional deployment network egress policies |
| Redirect to malicious server | HTTPS opener rejects HTTP redirects | Operational monitoring |
| Provider impersonation | Exact issuer match plus HTTPS origin restrictions | Confirm actual CERN discovery response |
| Plaintext or downgraded provider | HTTPS certificate verification; require PKCE S256 and `code` response type | Verify actual registered client configuration |
| Excessive response payload | 256 KiB maximum and bounded timeout | Rate limiting on any future externally exposed triggers |
| Duplicate JSON fields | Strict JSON parser rejects duplicate members and non-finite values | Future JWKS validation must implement similar strictness |
| Token algorithm confusion | Only approved asymmetric algorithm names are retained; never `none` or `HS*` | Cryptographic JWT validation, key binding and rotation |
| Secret leakage through logs | Probe prints only public endpoints and sanitized conclusions | Centralized redaction once credential-bearing endpoints exist |
| Malicious outbound network from tests | All tests use fakes; no network requested in CI | Optional manual live check before real login work |

## Operational requirements

- Running `uv run python scripts/check_cern_oidc_discovery.py` performs **no network request**.
- Running it with `--live` performs **one public metadata GET** from the fixed CERN discovery URL; it does not register a client, authenticate a user or fetch the JWKS itself.
- Treat an unavailable endpoint, unexpected issuer or missing advertised S256 support as **NOT_VERIFIED**, not as permission to lower security requirements.
- Never attach `.env`, OAuth callbacks, cookies, codes, ID tokens, refresh tokens, client secrets or raw authorization headers to issues or chat.
- For hosted execution, introduce explicit outbound network policy and approved persistent session storage before enabling SSO.
- The private repository is not an officially supported CERN/ATLAS product.
