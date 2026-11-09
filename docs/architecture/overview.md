# Architecture overview

## Scope

Phase 0 establishes an independently deployable **modular monolith**. The application uses
ports and adapters: domain rules and application contracts know nothing about infrastructure,
while concrete integrations will implement those contracts.

```text
Web UI / CLI --> HTTP API --> Application --> Domain
                                      ^
                                      |
                            Infrastructure adapters
```

The first API includes read-only health, capability discovery, and a **synthetic** provenance
trace. No real document retrieval, code execution, or CERN authentication has been implemented.

## Dependency rules

1. `asca.domain` only imports Python standard-library modules.
2. `asca.application` may import domain types and standard-library modules, but no web frameworks.
3. `asca.api` implements transport and schema translation.
4. Infrastructure adapters will implement application ports, never the reverse.
5. The UI is a separate application and never assumes a knowledge provider is online.
6. Source code and external documents are untrusted until checked against policy.

## First domain model

`ProvenanceTrace` ensures that a decision's evidence IDs, code symbol IDs, and verification IDs
resolve against actual entries. The synthetic fixture is not science-backed and labels itself
as such. Future storage will preserve source versions, code revisions, proof status, and human
approvals, without inventing official ATLAS endorsements.

## Planned integrations

- CERN SSO: OIDC via registered application, no browser token scraping.
- chATLAS: read-only MCP discovery and queries, subject to authorization.
- CERN GitLab: scoped API access with traceable code revisions.
- Ollama: provider adapter for plan/code generation, never direct shell access.
- Execution: separate isolated runner with explicit authorization.

See [ADR-0001](../adr/0001-modular-monolith.md) and
[ADR-0002](../adr/0002-evidence-boundaries.md).
