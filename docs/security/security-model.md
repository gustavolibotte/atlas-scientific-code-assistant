# Security model

## Phase 0

The API exposes GET-only demonstration endpoints. CORS is restricted to local Vite origins.
The UI cannot execute code, read arbitrary local paths, or authenticate users.

## Future identity

- Register an official OIDC client in the CERN Application Portal.
- Prefer Authorization Code with PKCE for desktop/public clients.
- Keep access tokens outside prompts and logs.
- Authenticate to each source with appropriate audience and scopes; CERN login alone does
  not imply permission to query chATLAS or GitLab.
- Treat authorization failures as denied, never as empty search results.

## Future agent execution

- Evaluate permission before every tool invocation.
- Do not rely on a Conda environment as a security sandbox.
- Run untrusted generated code in an isolated executor with network and resource limits.
- Distinguish public, collaboration-internal, and restricted source content in exports.
- Treat retrieved pages and repository files as untrusted input, not system instructions.

## Threat model additions before Phase 1

Document token storage, session revocation, CSRF, SSRF, dependency compromise,
symlink/path traversal, prompt injection, and output exfiltration scenarios.
