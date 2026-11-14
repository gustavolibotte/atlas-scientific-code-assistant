# Changelog

## Unreleased

- Roadmap v2: evidence-to-code vertical milestones M1–M10 (ADR 0037, accepted).
- CERN web authorization track frozen at Phase 1A.2.5C9; existing code and tests unchanged.
- `CLAUDE.md` working agreement for Claude Code sessions.
- M1 persisted evidence and provenance core (ADR 0038):
  - per-project, append-only provenance graph with derived decision status, approval
    fingerprints, hash-bound quote checks, two currency dimensions and link freshness;
  - SQLite persistence with SQLAlchemy 2 and Alembic (append-only triggers, revision
    compare-and-set, full revalidation on load); `ASCA_DATABASE_URL` selects the database
    for `make api`, which defaults to `./.asca/asca.db`;
  - versioned, handwritten JSON Schemas (`urn:asca:schema:<name>:v1`) and reproducible
    exports for `evidence_manifest`, `decision_records` and `validation_report`, with
    whole-record withholding by audience;
  - read-only GET routes for projects, symbols, function inspection and exports, and a
    `provenance_store` capability;
  - `/api/v1/demo/trace` keeps its contract, is served from the stored synthetic project
    and is marked deprecated.
- M2 code symbol index and link staleness (ADR 0039):
  - fingerprint algorithm `python-ast/1`: a canonical serializer over a pinned AST field
    table, insensitive to formatting, comments and docstrings, and identical on Python
    3.11, 3.12 and 3.13;
  - `PythonAstExtractor` (module, class, function and method symbols with spans; its own
    encoding allowlist; never executes, imports or compiles indexed code) and a bounded,
    fd-relative `FilesystemWorkspaceReader` that never follows symlinks, never blocks and
    fails closed on every limit;
  - `IndexingService`, the only writer of indexed revisions, and a read-only preview
    CLI, `python -m asca.infrastructure.indexing ROOT`; there is no HTTP trigger;
  - link freshness by symbol lineage across revisions: an edited body is `stale`, a
    rename or file move without a body change is `moved`, a removed symbol is
    `orphaned`, and an unparseable or unreadable file is `unknown`, never `orphaned`;
  - migration `0002` adds `code_symbols.fingerprint_algorithm`,
    `workspace_revisions.source_digest` and `workspace_revisions.file_issues`;
  - additive API fields: freshness reason, linked, current and last-seen symbol
    locations, relocation candidates, file issues and a link-health list. The v1 export
    schemas and goldens are unchanged.

## 0.1.0 — Foundation (Phase 0)

- Independent repository with typed domain entities and provider contracts.
- Read-only FastAPI health, capability, and synthetic provenance endpoints.
- Responsive React workspace shell with an explicit demo state.
- Unit, property, contract, architecture, frontend, and security checks.
- Automated diagnostics bundle for external review.
- Initial architecture, design, testing, and security documentation.
