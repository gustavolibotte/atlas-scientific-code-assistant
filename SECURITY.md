# Security policy

This foundation contains read-only public demonstration routes. No authentication, MCP
client, arbitrary shell command execution, user file writes, or secrets storage is provided.

The future CERN SSO integration must use an officially registered OIDC application,
Authorization Code + PKCE for public clients, explicit scope checks, and token isolation.

External documents are data, never instructions. No model-generated commands will run
without a policy decision and execution isolation.

Report security vulnerabilities privately to the repository maintainers. Do not include
credentials or private collaboration content in issue reports.
