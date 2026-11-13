# ADR 0038: Persisted provenance graph and versioned export contracts

- **Status:** Proposed (2026-11-13); accepted when the M1 pull request merges
- **Date:** 2026-11-13
- **Milestone:** M1 (Persisted evidence and provenance core), `docs/roadmap.md` v2
- **Related:** [ADR 0001](0001-modular-monolith.md), [ADR 0002](0002-evidence-boundaries.md),
  [ADR 0037](0037-prioritize-evidence-to-code-vertical-slice.md)

## Context

Until M1 the application served one in-code synthetic trace (`ProvenanceTrace`). M1 must
create, persist, reload and export a complete evidence-to-code trace, check the roadmap
invariants with property tests, and serve the API from storage instead of the fixture.

Three choices shape every later milestone: where the consistency boundary lies, how a
decision's status is kept honest when evidence changes, and which file formats leave the
application. This ADR records them, together with the constraints that the existing,
frozen route allowlist puts on new HTTP routes.

## Decision

### 1. Per-project consistency boundary

One immutable `ProvenanceGraph` per project is the unit of loading, validation and
writing. The graph holds sources, source versions, supersession notices, claims, claim
checks, decisions, evidence links, workspace revisions, code symbols, implementation
links, test cases, verification links, environment snapshots, validation runs and
approvals. Every record carries its `project_id`; the graph rejects records of another
project.

- **State invariants** (G rules) run in the graph constructor, so they are checked on
  every load from storage, not only on writes.
- **Transition rules** (T rules) run only in `ProvenanceGraph.append`, against the base
  graph plus the earlier records of the same batch.
- The application `ProvenanceService` only writes and loads. Inspection
  (`asca.application.inspection`) and export (`asca.application.exports`) are pure
  functions over a loaded graph.

### 2. Append-only records and revision compare-and-set

- The `ProvenanceRepository` port has `create_project`, `load`, `list_projects` and
  `append(project_id, expected_revision, records)`. It has no update and no delete.
- `append` is the transaction boundary. It inserts all records and advances
  `projects.revision` by one only when the stored revision equals `expected_revision`;
  otherwise it raises `ConcurrentModificationError`. A write lock held by another
  connection is reported the same way.
- In SQLite, triggers abort every `UPDATE` and `DELETE` on the 16 record tables
  (`append-only`). On `projects`, only `revision` may change and rows cannot be deleted.
- Every record row stores `added_in_revision` (persistence only), which enables future
  as-of loads without changing the domain.
- Re-checking a claim appends a new `ClaimCheck` (sequence 1..n per claim); changing a
  decision appends a new `ScientificDecision` with `supersedes_id`. A superseded decision
  is frozen: it takes no new links or approvals.
- Foreign keys are single-column. Project scope is enforced by the domain on every load.
  Composite tenant foreign keys are deferred to M10.
- Load errors of any kind (constraint drift, malformed JSON, unknown enum value, a
  violated G rule) are wrapped as `StoredGraphIntegrityError` and mapped to a generic
  HTTP 500 that never echoes ids, SQL or URLs.

### 3. Derived status and the approval fingerprint

A decision's status is never stored. `derive_status` computes it from the graph:

- the **evidential status** is `supported`, `conflicting`, `proposed` or `unsupported`,
  from *countable* links: stance `supports` or `contradicts`, claim state
  `source_text_checked`, and a source version whose authority can support (anything but
  `automated_inference`). `context` links never count;
- an approval is a record with a verdict. `approved` requires evidential status
  `supported`, or `conflicting` with a written `conflict_resolution`. A rejection is
  final. Synthetic projects cannot have approvals;
- each approval stores the decision's **support fingerprint**, a sha256 over the sorted
  countable-stance links (link, stance, claim, claim state, authority). When the
  evidence changes after an approval, the fingerprint differs, the approval becomes
  stale, the status falls back to the evidential status and `APPROVAL_STALE` is reported.

This satisfies the roadmap invariants: `approved` requires an `Approval`, and a
`supported` decision needs at least one `source_text_checked` claim.

### 4. Quote checking bound to the content hash

`source_text_checked` is produced only by the domain function `check_quote(claim,
version, text, ...)`. The caller supplies the source text; its sha256 must equal the
version's stored `content_sha256`, otherwise nothing is recorded. The quote is matched
as a normalized substring (NFKC, soft hyphens removed, whitespace collapsed;
normalization version 1). Source text itself is not persisted in M1. A check that could
not be performed is recorded as `unavailable` with a reason.

### 5. Authority and access on the version; two currency dimensions

- `SourceAuthority` (`published` A, `approved_internal` B, `verified_implementation` C,
  `working_material` D, `automated_inference` E) and `AccessClass` (`public`,
  `internal`, `restricted`) live on `SourceVersion`, not on `Source`. They are ASCA
  project policy, not an official ATLAS classification.
- `published` authority requires a non-synthetic source with a persistent identifier of
  a published scheme (checked at graph level) and public access.
- Currency is derived from append-only `SupersessionNotice` records in two dimensions,
  **scientific** and **technical**. Currency is reported as a status reason but never
  changes the evidential status.

### 6. Access high-water mark and export withholding

- A decision's `effective_access_class` is the most restrictive of its own
  `access_floor` and the access classes of every linked claim's version, including
  `context` links.
- An export for an audience includes a record only when the audience permits its class.
  Withheld sources, versions, claims and decisions are removed **whole** and listed in a
  `withheld` array (`kind`, `id`, `access_class`). Decision text follows the decision's
  effective class, so internal evidence cannot leak through a decision's statement.
- In local single-user mode the inspection API returns every access class. The route
  carries `# M10: filter by viewer before any non-loopback deployment`.

### 7. Identifier format

Every record id is `<3-letter kind>_<32 lowercase hex>` (for example `prj_…`, `dec_…`,
`sym_…`), validated by kind on construction. Production ids come from uuid4; the demo and
the tests use a deterministic sha256 counter per kind. Environment snapshots are
project-scoped and content-addressed: the hashed content includes the `project_id`.

### 8. Persistence and migration policy

- SQLAlchemy 2 (sync) and Alembic on SQLite, behind the repository port. Only
  `sqlite+pysqlite:///` URLs are accepted in M1; any other URL is refused with a fixed
  message that never echoes it.
- `create_app(database_url="sqlite+pysqlite:///:memory:", *, seed_demo=True, clock=None,
  ids=None)` builds the store eagerly, migrates it to head, seeds the synthetic
  demonstration project idempotently and never reads environment variables. The default
  in-memory database touches no file. The lifespan only disposes the engine.
- `create_app_from_environment()` is the only entry point that reads
  `ASCA_DATABASE_URL` (default `sqlite+pysqlite:///./.asca/asca.db`). For a relative file
  path it creates the parent directory with mode `0o700`. `make api` uses it.
- File databases use foreign keys, WAL and a 5 s busy timeout, and real SQLite
  transactions so that a load reads one snapshot.
- Migrations are handwritten (no autogenerate, no `create_all` in production paths) and
  run programmatically on startup from the packaged `migrations` directory.
- **Policy:** migrations are immutable after merge; revision ids are 4-digit sequential
  (`0001`, `0002`, …); there is always exactly one head; every migration has a
  downgrade. Tests enforce one head, the id format, the downgrade/upgrade round trip and
  that the migrated schema equals the ORM metadata.
- The migration writes enum columns as `VARCHAR(32)` with explicit `CHECK … IN (…)`
  constraints and does not import domain enums, so it stays fixed if the enums change.
- No PostgreSQL DDL or CI in M1. PostgreSQL triggers and compatibility tests come with
  the PostgreSQL milestone.

### 9. Export schema versioning and lock

- Three export artifacts: `evidence_manifest`, `decision_records`,
  `validation_report`. Schemas are handwritten JSON Schema Draft 2020-12 in the
  stdlib-only data package `asca.contracts`, with `$id` `urn:asca:schema:<name>:v1`,
  `additionalProperties: false` at every level and self-contained `$defs`.
- Every enum in a schema equals its domain `StrEnum` (tested).
- `contracts/exports/released.json` holds the sha256 of each released schema file. v1 is
  frozen: **any** change to the set of accepted instances requires a new `v2/` directory
  and a new URN. Description-only edits bump the patch of `schema_version` and update
  the lock with reviewer sign-off.
- Exports carry no timestamp. They are a pure function of
  `(graph, artifact, audience, generator_version)`, serialized as canonical JSON
  (sorted keys, two-space indent, UTF-8, trailing newline), so output is byte
  reproducible. `project.revision` pins the exact state.
- `GET /api/v1/projects/{project_id}/exports/{artifact}?audience=…` returns the bytes with
  `Content-Disposition: attachment` and `X-ASCA-Schema`. Writing export files is M5.

### 10. Frozen legacy endpoint

`GET /api/v1/demo/trace` keeps its response shape, OpenAPI component names and enum
values; the legacy enums now live in `asca.api.schemas`. It is built from the stored
demonstration project by `legacy_trace_from_graph`, is marked `deprecated=True`, and a
golden file pins its output. Only the id values changed. The web UI is unchanged.

### 11. Route-allowlist amendment

`tests/security/test_oidc_authorization_boundary_security.py` asserts the exact set of
API routes. M1 makes one additive edit to that set: four GET tuples.

- `/api/v1/projects`
- `/api/v1/projects/{project_id}/symbols`
- `/api/v1/projects/{project_id}/symbols/{symbol_id}/inspection`
- `/api/v1/projects/{project_id}/exports/{artifact}`

Nothing else in that file or in any identity/OIDC source changes. The intent of the test
(GET only, no login or callback routes) is kept and reinforced by
`tests/security/test_provenance_api_security.py`.

The installed FastAPI turns `app.include_router` into one lazy route entry, which the
allowlist test (it counts `APIRoute` objects in `app.routes`) would not see. The
composition root therefore adds router routes directly through `_mount_routes`, so both
frozen route checks really cover the new operations. A guard test fails if the new
operations stop appearing as `APIRoute` entries.

## Open questions for the maintainer (defaults already applied)

| # | Question | Default in M1 |
|---|---|---|
| 1 | Is the one-line, additive amendment to the frozen route-allowlist test acceptable? | Applied. If refused, M1 ships without the four new routes; the exit criterion is still met by the legacy endpoint served from storage, and inspection and export are tested at application level only. |
| 2 | Strict approval policy: should unsupported or proposed decisions be approvable, for example through an `expert_judgment` approval basis in M4? | No. Only `supported`, or `conflicting` with a conflict resolution, can be approved. |
| 3 | Automated relevance: should an `asserted_by=automated` link to a human-checked quote need human confirmation before it counts as support (M4)? | No. It counts as support; the link origin is shown in inspection and exports. |
| 4 | High-water access: one internal claim withholds the whole decision from public exports. Confirm? | Yes, the whole decision is withheld and listed in `withheld`. |
| 5 | Reviewer labels in exports are personal data inside files that leave the application. Confirm before M5? | Reviewer labels are exported as stored; to be confirmed before M5 writes export files. |

## Consequences

- The UI keeps working unchanged, now from stored data. The Function Inspector UI (M7)
  builds on the new OpenAPI document, contract tests and golden files.
- Status can never be inconsistent in storage because it is not stored. The price is
  recomputation on every read, which is acceptable for per-project graphs of M1 size.
- Every load revalidates the whole graph, so a tampered or drifted database fails loudly
  (`StoredGraphIntegrityError`) instead of serving wrong provenance.
- The default in-memory store is one shared SQLite connection (`StaticPool`); concurrent
  requests share it without isolation. It is meant for tests and ephemeral runs; local
  use goes through a file database.
- Coverage measured by module name (`--cov=asca`) reports the Alembic `env.py` and the
  `0001` revision as unexecuted because Alembic imports them under its own module names;
  the migration tests do execute them.
- M2 (symbol indexing) can produce `stale`, `moved` and `orphaned` freshness without an
  export-schema major bump, because `LinkFreshness` already includes them.
- Non-goals of M1: write HTTP API, authentication, viewer-based filtering, PostgreSQL,
  composite tenant keys, persisted source text, import of exported bundles, export file
  writing, retraction or erasure records.
