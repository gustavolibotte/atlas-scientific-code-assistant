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

## 0.1.0 — Foundation (Phase 0)

- Independent repository with typed domain entities and provider contracts.
- Read-only FastAPI health, capability, and synthetic provenance endpoints.
- Responsive React workspace shell with an explicit demo state.
- Unit, property, contract, architecture, frontend, and security checks.
- Automated diagnostics bundle for external review.
- Initial architecture, design, testing, and security documentation.
