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

The API is read-only: health, capability discovery, a persisted provenance store with function
inspection and versioned exports, and the deprecated legacy trace, which is now served from a
stored **synthetic** demonstration project. No real document retrieval, code execution, or CERN
authentication has been implemented.

## Dependency rules

1. `asca.domain` only imports Python standard-library modules.
2. `asca.application` may import domain types and standard-library modules, but no web frameworks.
3. `asca.api` implements transport and schema translation.
4. Infrastructure adapters will implement application ports, never the reverse.
5. The UI is a separate application and never assumes a knowledge provider is online.
6. Source code and external documents are untrusted until checked against policy.

## Provenance domain model (M1)

`asca.domain.provenance` holds one immutable `ProvenanceGraph` per project: sources and their
versions (authority, access class, content hash), supersession notices, claims with append-only
claim checks, scientific decisions, evidence and implementation and verification links, workspace
revisions and code symbols, test cases, environment snapshots, validation runs and approvals.

- State invariants run on every load; transition rules run on every append.
- Decision status is derived, never stored. A `supported` decision needs a checked quote
  (`source_text_checked`), whose source text must match the version's content hash. An
  approval stores a support fingerprint and goes stale when the evidence changes.
- A decision's effective access class is the most restrictive class of its evidence. Exports
  withhold whole records the audience may not see.
- `ProvenanceService` (application) writes through the `ProvenanceRepository` port. The SQLite
  adapter in `asca.infrastructure.persistence` (SQLAlchemy 2, Alembic) is append-only and
  advances a per-project revision with compare-and-set.
- Inspection (`asca.application.inspection`) and exports (`asca.application.exports`, schemas
  in `asca.contracts`) are pure functions over a loaded graph.

The demonstration project is synthetic, is not science-backed and labels itself as such. No
official ATLAS endorsement is inferred. See
[ADR-0038](../adr/0038-persisted-provenance-graph-and-export-contracts.md).

## Code symbol index and link lineage (M2)

`asca.infrastructure.indexing` turns a workspace into one symbol-indexed revision:

- `filesystem.FilesystemWorkspaceReader` implements the `WorkspaceReader` port. It walks
  one local tree with fd-relative, no-follow, non-blocking opens, enforces the
  `IndexLimits` and fails closed; POSIX only.
- `python_symbols.PythonAstExtractor` implements the `SymbolExtractor` port: module,
  class, function and method symbols with spans, decoded with its own encoding
  allowlist. `python_fingerprint` computes the `python-ast/1` fingerprints. Both are pure
  standard-library modules that never execute, import or compile indexed code.
- `__main__` is a read-only preview CLI (`python -m asca.infrastructure.indexing ROOT`)
  that prints one JSON line and touches no database.

`IndexingService` (`asca.application.indexing`) is the only writer of indexed revisions;
there is no HTTP trigger. The domain stores opaque `(algorithm, sha256)` fingerprints
and per-revision file issues, and `SymbolLineage` (`asca.domain.provenance.lineage`)
derives link freshness by following each symbol across revisions: `current`, `stale`,
`moved`, `orphaned`, or `unknown` when its file could not be parsed. The inspector and
the GET routes expose the lineage additively; the v1 export schemas are unchanged. See
[ADR-0039](../adr/0039-python-symbol-index-and-link-lineage.md).

## Federated knowledge layer (M3)

`asca.application.knowledge` holds the async `KnowledgeProvider` models, PID rules, the
`asca-authority/1` suggestion policy, the `FederationService` and registration planning.
`asca.infrastructure.knowledge` implements the port:

- `inspire`, `arxiv` and `hepdata` (search only) over one bounded httpx2 client
  (`http`): fixed base URLs, TLS always verified, no redirects, byte caps, generic
  User-Agent, provider spacing, no retries; XML only through `defusedxml`;
- `local`, a curated library described by a manifest, read with the M2 filesystem
  reader;
- `mcp_client`, a generic MCP client (one session per operation, configured tools only,
  results as data) with `mcp_stdio_guard` bounding stdio servers;
- `config` (permission-checked TOML, never the working directory), `settings`,
  `secrets` (environment-only `ASCA_` variables) and `url_guard`;
- `factory.build_federation` and the CLI `python -m asca.infrastructure.knowledge`
  (`search`, `fetch`, `health`, `providers`).

Every configured provider is reported, results are grouped by identity PIDs without
fusing fields, and every network call needs `--live`. There is no HTTP route in M3.
See [ADR-0040](../adr/0040-federated-knowledge-layer.md).

## Planned integrations

- CERN SSO: OIDC via registered application, no browser token scraping.
- chATLAS: read-only MCP queries through the generic M3 MCP client, subject to
  authorization (access probe and ADR 0041 pending).
- CERN GitLab: scoped API access with traceable code revisions.
- Ollama: provider adapter for plan/code generation, never direct shell access.
- Execution: separate isolated runner with explicit authorization.

See [ADR-0001](../adr/0001-modular-monolith.md) and
[ADR-0002](../adr/0002-evidence-boundaries.md).
