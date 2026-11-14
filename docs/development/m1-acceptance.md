# M1 — Persisted evidence and provenance core: acceptance

Milestone definition: [`docs/roadmap.md`](../roadmap.md) (M1). Architecture and policy:
[ADR 0038](../adr/0038-persisted-provenance-graph-and-export-contracts.md).

## Scope

- Per-project, append-only provenance graph in `asca.domain.provenance`, with derived
  decision status, approval fingerprints, hash-bound quote checks, two currency
  dimensions and link freshness.
- `ProvenanceService` over the `ProvenanceRepository` port; in-memory and SQLite
  (SQLAlchemy 2 + Alembic) repositories.
- Handwritten, versioned JSON Schemas for `evidence_manifest`, `decision_records` and
  `validation_report`, with a `released.json` hash lock, and pure export builders.
- Function inspection read model and four read-only GET routes; the legacy
  `/api/v1/demo/trace` contract served from the stored demonstration project.
- `create_app(database_url=...)` composition on SQLite and `create_app_from_environment()`
  reading `ASCA_DATABASE_URL`.
- No frontend change, no write HTTP API, no authentication, no PostgreSQL.

## Exit criteria and the tests that prove them

Test ids are relative to the repository root and run with `uv run pytest -q <id>`.

### Domain model extension

`Source`, `SourceVersion` (content hash, retrieval time, access class, authority), `Claim`
(quote, locator, verification state), `ScientificDecision` (status, alternatives,
assumptions), `CodeSymbol`, `TestCase`, `ValidationRun`, `Approval`,
`EnvironmentSnapshot`:

- `tests/unit/test_provenance_records.py::test_source_version_rules`
- `tests/unit/test_provenance_records.py::test_claim_rules`
- `tests/unit/test_provenance_records.py::test_claim_check_shape_matrix`
- `tests/unit/test_provenance_records.py::test_decision_rules`
- `tests/unit/test_provenance_records.py::test_code_and_test_rules`
- `tests/unit/test_provenance_records.py::test_validation_run_rules`
- `tests/unit/test_provenance_records.py::test_environment_snapshot_is_content_addressed`
- `tests/unit/test_provenance_records.py::test_every_record_type_is_frozen`
- `tests/unit/test_provenance_status.py::test_exhaustive_status_table` (every status
  `proposed | supported | unsupported | conflicting | approved | rejected`)
- `tests/unit/test_provenance_service.py::test_complete_project_has_the_expected_statuses`

### Invariant: `approved` requires an `Approval`

- `tests/unit/test_provenance_status.py::test_exhaustive_status_table`
- `tests/unit/test_provenance_status.py::test_status_soundness_over_valid_graphs` (property)
- `tests/unit/test_provenance_status.py::test_valid_graphs_reach_every_interesting_status`
  (the strategy behind the properties generates supported, conflicting, approved and
  rejected decisions)
- `tests/unit/test_provenance_status.py::test_mismatch_after_approval_makes_it_stale_and_unsupported`
- `tests/unit/test_provenance_graph.py::test_transition_rules_for_approvals`
- `tests/unit/test_provenance_graph.py::test_same_batch_approval_checks_use_the_earlier_records`
- `tests/unit/test_provenance_graph.py::test_an_approval_before_its_decision_in_the_batch_is_refused`
- `tests/unit/test_provenance_graph.py::test_batch_order_of_approvals_must_follow_their_sequence`
- `tests/unit/test_provenance_graph.py::test_synthetic_projects_cannot_have_approvals`
- `tests/contract/test_export_schemas.py::test_approved_decision_without_reviews_is_rejected`
- `tests/contract/test_export_schemas.py::test_stale_approved_decision_is_rejected`

### Invariant: `published` authority requires a real source with a persistent identifier

- `tests/unit/test_provenance_graph.py::test_published_needs_a_published_identifier` (property)
- `tests/unit/test_provenance_graph.py::test_published_identifier_schemes_are_accepted`
- `tests/unit/test_provenance_graph.py::test_synthetic_source_rules`
- `tests/unit/test_provenance_graph.py::test_implementation_and_synthetic_authority_rules`
- `tests/unit/test_provenance_values.py::test_persistent_identifier_patterns`

### Invariant: a `supported` decision needs at least one `source_text_checked` claim

- `tests/unit/test_provenance_status.py::test_status_soundness_over_valid_graphs` (property)
- `tests/unit/test_provenance_status.py::test_automated_inference_links_never_change_evidential_status` (property)
- `tests/unit/test_provenance_status.py::test_context_links_never_change_status_or_fingerprint` (property)
- `tests/unit/test_provenance_quote.py::test_any_slice_with_content_is_source_text_checked` (property)
- `tests/unit/test_provenance_quote.py::test_any_wrong_text_raises_content_hash` (property)
- `tests/unit/test_provenance_service.py::test_wrong_text_raises_and_records_nothing`
- `tests/contract/test_export_schemas.py::test_supported_decision_without_a_checked_support_item_is_rejected`

### Persistence: SQLAlchemy 2 + Alembic on SQLite behind repository ports

- `tests/contract/test_provenance_persistence.py::test_complete_project_survives_engine_disposal_and_reopen`
- `tests/contract/test_provenance_persistence.py::test_replayed_scripts_load_identically_from_sqlite_and_memory` (property)
- `tests/contract/test_provenance_state_machine.py::TestPersistenceParity` (stateful property)
- `tests/contract/test_provenance_persistence.py::test_second_writer_on_a_stale_revision_is_refused`
- `tests/contract/test_provenance_persistence.py::test_constraint_violation_rolls_back_the_whole_append`
- `tests/contract/test_provenance_persistence.py::test_seeded_demo_loads_identically_from_sqlite_and_memory`
- `tests/contract/test_provenance_persistence.py::test_concurrent_loads_on_the_shared_in_memory_store_return_the_stored_graph`
- `tests/contract/test_provenance_persistence.py::test_concurrent_first_start_on_a_fresh_file_migrates_once`
- `tests/contract/test_provenance_migrations.py::test_upgraded_schema_matches_the_orm_metadata`
- `tests/contract/test_provenance_migrations.py::test_downgrade_to_base_leaves_only_the_version_table_and_upgrade_works_again`
- `tests/contract/test_provenance_migrations.py::test_there_is_exactly_one_head_and_revision_ids_are_four_digits`
- `tests/security/test_provenance_store_security.py::test_record_rows_cannot_be_updated`
- `tests/security/test_provenance_store_security.py::test_record_rows_cannot_be_deleted`
- `tests/security/test_provenance_store_security.py::test_tampered_check_hash_fails_the_load`
- `tests/security/test_provenance_store_security.py::test_unsupported_urls_are_refused_without_echoing_them`
- `tests/architecture/test_dependencies.py::test_api_never_touches_persistence_libraries`
- `tests/architecture/test_dependencies.py::test_application_imports_only_stdlib_domain_application_and_contracts`

### Versioned JSON Schemas for the three exported artifacts

- `tests/contract/test_export_schemas.py::test_the_three_artifacts_are_named_consistently`
- `tests/contract/test_export_schemas.py::test_schema_is_a_valid_draft_2020_12_schema_with_its_urn`
- `tests/contract/test_export_schemas.py::test_schema_file_hash_matches_the_released_lock`
- `tests/contract/test_export_schemas.py::test_every_enum_lives_in_defs_and_equals_its_str_enum`
- `tests/contract/test_export_schemas.py::test_exports_of_valid_graphs_validate_for_every_audience` (property)
- `tests/unit/test_provenance_exports.py::test_demo_exports_match_the_golden_bytes`
- `tests/unit/test_provenance_exports.py::test_shuffled_graph_tuples_give_identical_bytes`
- `tests/security/test_provenance_export_security.py::test_withheld_text_never_reaches_a_less_privileged_export`

### Exit: create, persist, reload and export a complete trace

- `tests/contract/test_provenance_api_persistence.py::test_stored_trace_survives_a_restart_on_the_same_file`
  (records the complete project through the application on a SQLite file, then a second
  application on the same file serves identical inspection, symbol, trace and export
  responses for every artifact and audience, without re-seeding)
- `tests/contract/test_provenance_persistence.py::test_complete_project_survives_engine_disposal_and_reopen`
- `tests/unit/test_provenance_exports.py::test_complete_project_decision_records`
- `tests/unit/test_provenance_exports.py::test_complete_project_validation_report`
- `tests/unit/test_provenance_exports.py::test_complete_project_manifest_versions_and_claims`
- `tests/contract/test_export_schemas.py::test_demo_and_complete_project_exports_validate_for_every_audience`

### Exit: property tests for invariants

- `tests/unit/test_provenance_status.py::test_status_soundness_over_valid_graphs`
- `tests/unit/test_provenance_status.py::test_effective_access_is_the_high_water_mark`
- `tests/unit/test_provenance_status.py::test_derive_status_is_deterministic_over_tuple_order`
- `tests/unit/test_provenance_graph.py::test_replacing_any_reference_with_a_fresh_id_is_dangling`
- `tests/unit/test_provenance_graph.py::test_permutation_invariance`
- `tests/contract/test_provenance_state_machine.py::TestPersistenceParity`

### Exit: the API serves a stored trace instead of the in-code fixture

- `tests/contract/test_legacy_trace.py::test_legacy_trace_matches_the_golden_file`
- `tests/contract/test_legacy_trace.py::test_unseeded_app_has_no_in_code_fixture`
- `tests/contract/test_provenance_api_persistence.py::test_the_legacy_trace_is_served_from_storage`
- `tests/contract/test_provenance_api.py::test_demo_symbols_to_inspection_round_trip`
- `tests/contract/test_provenance_api.py::test_complete_project_inspection_key_sets_and_enum_values`
- `tests/contract/test_api.py` (unchanged legacy contract)

### Composition and configuration

- `tests/contract/test_provenance_api_persistence.py::test_create_app_without_arguments_creates_no_file`
- `tests/contract/test_provenance_api_persistence.py::test_create_app_from_environment_honours_the_database_url`
- `tests/contract/test_provenance_api_persistence.py::test_default_environment_database_lives_in_a_private_local_directory`
- `tests/contract/test_provenance_api_persistence.py::test_unsupported_environment_url_is_refused_without_side_effects`
- `tests/contract/test_provenance_api_persistence.py::test_application_shutdown_disposes_the_store`
- `tests/contract/test_provenance_api_persistence.py::test_an_interrupted_first_start_is_completed_by_the_next_start`
- `tests/unit/test_provenance_demo.py::test_concurrent_seeders_converge_on_the_complete_demo`
- `tests/unit/test_provenance_demo.py::test_a_foreign_project_with_the_demo_id_fails_loudly`

### Security boundary of the new routes

- `tests/security/test_oidc_authorization_boundary_security.py::test_only_read_only_foundation_api_routes_are_exposed`
  (amended additively with the four GET routes; see ADR 0038, section 11)
- `tests/security/test_provenance_api_security.py::test_write_methods_are_not_allowed`
- `tests/security/test_provenance_api_security.py::test_malformed_project_ids_are_rejected`
- `tests/security/test_provenance_api_security.py::test_not_found_bodies_do_not_echo_ids`
- `tests/security/test_provenance_api_security.py::test_integrity_errors_are_generic_500s`
- `tests/security/test_provenance_api_security.py::test_untrusted_cors_origin_is_not_allowed`
- `tests/security/test_provenance_api_security.py::test_security_headers_on_inspection_and_export_responses`
- `tests/security/test_provenance_api_security.py::test_validation_errors_never_echo_the_rejected_value`
- `tests/contract/test_provenance_api.py::test_validation_errors_match_the_published_openapi_schema`
- `tests/security/test_provenance_export_security.py::test_a_test_verifying_public_and_restricted_decisions_follows_the_restricted_one`

## Quality gates

All gates from `CLAUDE.md` must pass before merge:

```bash
uv run ruff check src tests scripts prototypes
uv run ruff format --check src tests scripts prototypes
uv run mypy src
uv run pytest -q --cov=asca --cov-branch --cov-fail-under=85
cd apps/web && npm ci && npm run typecheck && npm run test:run && npm run build
```

The frontend is unchanged in M1, so its gate is expected to pass unchanged.

## Open questions

The maintainer questions and their applied defaults are listed in ADR 0038 under
"Open questions for the maintainer".
