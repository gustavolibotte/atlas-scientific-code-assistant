# Phase 1A.2.5C7 — local HTTPS mock BFF prototype

Scope: isolated runnable synthetic browser flow and negative tests. **Not** a
production ASCA authentication feature and **not** a CERN integration approval.

- [ ] Base is clean `main` commit `ee15f420c14c68e6b31cf51cc037181daad47522`.
- [ ] New branch `feat/cern-web-bff-mock-browser-lab-1a2-5c7`.
- [ ] Guarded installer adds only the prototype, test, README and checklist.
- [ ] Browser can navigate `/lab` -> `/mock/authorize` -> `/lab/callback`.
- [ ] Provider is ephemeral local-only mock; all inputs are synthetic.
- [ ] Token exchange is isolated in-process HTTP, not a real CERN backchannel.
- [ ] HTTPS loopback, Secure HttpOnly host-only pre-auth cookie, PKCE S256,
      bound state, nonce, RS256 signature, issuer and audience tests pass.
- [ ] Single-use codes, tickets, callback state, TTL and negative test cases pass.
- [ ] No authenticated ASCA session, access, role permission or actual CERN SSO.
- [ ] No existing source, API route, frontend, dependency or CI configuration is changed.
- [ ] Focused tests, Ruff, type gates and all eight quality gates pass.
- [ ] PR CI 13/13, post-merge CI 13/13, local post-merge gates 8/8.

This isolated mock does **not** close G1, G6, G7 or the other deployment gates.
Do not copy its issuer, in-memory stores, mock token issuer, or HTTP backchannel
into a production implementation. External CERN registration and official
positive assurance remain separate, supervised steps.
