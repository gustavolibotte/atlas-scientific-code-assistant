# Roadmap and acceptance gates

## Phase 0 — Foundation

- FastAPI service, independent domain and application contracts.
- Working React shell, backend status, synthetic provenance inspector.
- Architecture, contract, security, unit, property, and UI tests.
- A reproducible diagnostic ZIP.

## Phase 1 — Identity and discovery

Implement CERN OIDC registration and authentication, *then* assess authorized chATLAS MCP
tools. No assumption of service permissions. Mocked and negative authorization tests required.

## Phase 2 — Knowledge

Integrate provider ports, evidence catalog, source locator normalization and access classes.

## Phase 3 — Scientific decisions

Persist source-backed decisions and code-symbol/test relationships with versioned storage.

## Phase 4 — Agent

Implement controlled planning and code generation. Do not execute arbitrary model output.

## Phase 5 — Scientific workspace

Add code review, test reports, citations, and validated decision inspection.

## Phase 6+ — Isolated execution, ROOT, desktop and server deployment

Integrate sandboxed executors and controlled scientific benchmarks.
