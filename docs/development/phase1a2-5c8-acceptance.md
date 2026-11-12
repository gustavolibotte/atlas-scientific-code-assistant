# Phase 1A.2.5C8 — isolated real-provider CERN web diagnostic

- [ ] Branch created from clean `main` at `165f86aaf2a7fba8f278d156f4be7be0c314c707`.
- [ ] Guarded installer adds four files and modifies no existing files.
- [ ] The C7 mock remains unchanged, unmounted and on port 8443 when separately running.
- [ ] Real-provider probe binds strictly to 127.0.0.1 over HTTPS and accepts only
      `https://localhost:8443/oidc/callback`.
- [ ] Application registration is the independently configured CERN
      `asca-web-dev` confidential client; the native client is explicitly rejected.
- [ ] Client Secret entered via `getpass`, stored only in owner-readable ignored
      diagnostics, and never passed in CLI, frontend or code/repo artifacts.
- [ ] Authorization uses the existing ASCA state/PKCE service and bounded atomic
      in-memory store; callbacks are consumed before token HTTP POST.
- [ ] Provider discovery and JWKS always use the pinned CERN issuer and TLS.
- [ ] Code exchange uses HTTP Basic client authentication, explicit redirect
      URI, PKCE verifier, no redirects/proxy environment and bounded responses.
- [ ] Existing ASCA token parser and JWS/JWKS/claims pipeline are reused.
- [ ] No role or entitlement is promoted to trusted application authorization.
- [ ] No API routes, sessions, production login, frontend, dependencies or
      deployment changes are introduced.
- [ ] No HTTP access logging, forwarded headers, sensitive error output or
      personal claim diagnostic output.
- [ ] Focused tests pass on direct `pytest` invocation; no import path CI errors.
- [ ] Ruff lint + format, full backend pytest, and 8/8 local gates pass.
- [ ] Diff is exactly four added files with `git diff --check` clean.
- [ ] PR receives all 13 CI checks; post-merge receives 13 CI + 8 local gates.

**Stop condition:** a cryptographically checked ID token is still only a
non-authoritative diagnostic. G1/G6/G7 are not automatically cleared. No ASCA
session, user identity, permission or chATLAS/GitLab access may be activated.
