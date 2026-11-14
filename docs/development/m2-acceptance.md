# M2 — Code symbol index and link staleness: acceptance

Milestone definition: [`docs/roadmap.md`](../roadmap.md) (M2). Architecture and policy:
[ADR 0039](../adr/0039-python-symbol-index-and-link-lineage.md).

## Scope

- Fingerprint algorithm `python-ast/1`: a closed-world, iterative canonical serializer
  over a pinned AST field table, stable on Python 3.11, 3.12 and 3.13
  (`asca.infrastructure.indexing.python_fingerprint`).
- `PythonAstExtractor`: module, class, function and method symbols with qualified names,
  spans and fingerprints; its own PEP 263 allowlist decoder; it never executes, imports
  or compiles indexed code (`asca.infrastructure.indexing.python_symbols`).
- `FilesystemWorkspaceReader`: fd-relative, never follows symlinks, opens non-blocking,
  enforces limits and fails closed (`asca.infrastructure.indexing.filesystem`), and a
  read-only preview CLI, `python -m asca.infrastructure.indexing ROOT`.
- Application ports `WorkspaceReader` and `SymbolExtractor`, the pure `build_index` and
  `IndexingService`, the only writer of indexed revisions.
- Domain: `FingerprintAlgorithm`, `FileIssue`, revision `file_issues` and
  `source_digest`, symbol `fingerprint_algorithm`, and lineage-based link freshness
  (`SymbolLineage`, `SymbolTrace`, `FreshnessReason`).
- Read model: links and symbol-level tests attach to a symbol by lineage;
  `DecisionView.trace`, `FunctionInspection.file_issue` and `link_health`.
- Persistence: migration `0002` (additive columns only).
- API: additive fields on the existing GET responses only.
- No new HTTP route, no frontend change, no export-schema change, no golden
  regeneration.

## Exit criteria and the tests that prove them

Test ids are relative to the repository root and run with `uv run pytest -q <id>`.

**Roadmap exit criterion** ("editing a function body marks its links stale; renaming
without a body change is detected as a move") is proven end to end by
`tests/contract/test_symbol_index_end_to_end.py`. It writes a real temporary workspace,
reads it with `FilesystemWorkspaceReader`, extracts it with `PythonAstExtractor`, records
each revision with `IndexingService` into a SQLite file migrated to `0002`, and reads
the result through the inspector and the HTTP API:

| Workspace change after linking D1 to `estimate_amplitude` and D2 to `subtract_pedestal` | Expected link state | Test |
|---|---|---|
| Reformat, add comments and docstrings | `current` (`unchanged`) | `test_reformat_comments_and_docstring_keep_links_current` |
| Edit the body | `stale` (`content_changed`) | `test_editing_the_body_marks_the_link_stale` |
| Rename without a body change | `moved` (`relocated`); the inspector and the API show the new location | `test_rename_without_body_change_is_a_move` |
| Move to another file under the same name | `moved` (`relocated`) | `test_move_to_another_file_is_a_move` |
| Rename, then edit in a later revision | `stale` (`relocated_and_changed`) at the new location | `test_rename_then_edit_is_stale_at_new_location` |
| Delete the function | `orphaned` (`removed`), `lost_in_revision` set, listed first in link health | `test_deleting_the_function_orphans_the_link` |
| Syntax error in the file, then fixed | `unknown` (`file_not_parsed`), never `orphaned`; `current` again after the fix | `test_syntax_error_is_unknown_and_recovers` |
| File replaced by a symlink, or over the size limit | `unknown` (`file_not_parsed`) | `test_symlinked_or_oversized_file_is_unknown_not_orphaned` |

### 1. Python symbol extraction (kinds, qualified names, spans)

- `tests/unit/test_python_symbols.py::test_extractor_identity`
- `tests/unit/test_python_symbols.py::test_kinds_and_qualified_names`
- `tests/unit/test_python_symbols.py::test_conditional_definitions_are_symbols`
- `tests/unit/test_python_symbols.py::test_async_compound_and_try_star_blocks_are_transparent`
- `tests/unit/test_python_symbols.py::test_defs_inside_functions_and_lambdas_are_not_symbols`
- `tests/unit/test_python_symbols.py::test_duplicates_merge`
- `tests/unit/test_python_symbols.py::test_spans_include_decorators`
- `tests/unit/test_python_symbols.py::test_module_span_counts_physical_lines`
- `tests/unit/test_python_symbols.py::test_non_ascii_and_overlong_names_are_skipped_with_members`
- `tests/unit/test_python_symbols.py::test_qualified_name_limit_is_inclusive`
- `tests/unit/test_python_symbols.py::test_top_level_def_named___module___is_skipped`
- `tests/unit/test_indexing_service.py::test_index_workspace_records_sorted_drafts_with_algorithm_and_issues`
- `tests/unit/test_indexing_service.py::test_build_index_drafts_are_sorted_by_path_and_name`
- `tests/unit/test_indexing_service.py::test_skipped_definitions_are_counted`
- `tests/unit/test_provenance_records.py::test_symbol_fingerprint_algorithm_rules`
- `tests/contract/test_symbol_index_end_to_end.py::test_rev1_indexes_the_tree_into_the_migrated_store`

### 2. A fingerprint insensitive to formatting and comments

- `tests/unit/test_python_fingerprint.py::test_formatting_and_comments_do_not_change_fingerprints`
- `tests/unit/test_python_fingerprint.py::test_formatting_perturbations_keep_fingerprints` (property)
- `tests/unit/test_python_fingerprint.py::test_comment_insertion_on_repository_sources`
- `tests/unit/test_python_fingerprint.py::test_unparse_round_trip_on_repository_sources`
- `tests/unit/test_python_fingerprint.py::test_docstrings_and_no_op_strings_are_ignored`
- `tests/unit/test_python_fingerprint.py::test_equal_spellings`
- `tests/unit/test_python_fingerprint.py::test_semantic_differences`
- `tests/unit/test_python_fingerprint.py::test_semantic_mutations_change_fingerprints` (property)
- `tests/unit/test_python_fingerprint.py::test_rename_keeps_function_fingerprint`
- `tests/unit/test_python_fingerprint.py::test_recursive_rename_keeps_fingerprint`
- `tests/unit/test_python_fingerprint.py::test_class_rename_keeps_class_and_method_fingerprints`
- `tests/unit/test_python_fingerprint.py::test_method_edit_changes_class`
- `tests/unit/test_python_fingerprint.py::test_nested_def_edit_or_rename_changes_enclosing_function`
- `tests/unit/test_python_fingerprint.py::test_joined_strings_are_flattened_and_merged`
- `tests/unit/test_python_fingerprint.py::test_formatter_parenthesized_del_keeps_every_fingerprint`
- `tests/unit/test_python_fingerprint.py::test_del_targets_are_flattened`
- `tests/unit/test_python_fingerprint.py::test_del_target_order_and_content_still_matter`
- `tests/unit/test_python_fingerprint.py::test_serializer_is_iterative`

### 3. Cross-version stability (Python 3.11, 3.12, 3.13)

- `tests/contract/test_fingerprint_golden.py::test_expected_file_names_the_algorithm_and_the_spec_vectors`
- `tests/contract/test_fingerprint_golden.py::test_reference_vectors`
- `tests/contract/test_fingerprint_golden.py::test_normalization_vectors`
- `tests/contract/test_fingerprint_golden.py::test_corpus_matches_golden`
- `tests/contract/test_fingerprint_golden.py::test_py312_corpus`
- `tests/contract/test_fingerprint_golden.py::test_py313_corpus`
- `tests/contract/test_fingerprint_golden.py::test_newer_corpora_are_syntax_errors_on_older_interpreters`
- `tests/unit/test_python_fingerprint.py::test_field_table_covers_running_interpreter`
- `tests/unit/test_python_fingerprint.py::test_pep695_distinguished`

The golden module runs on each supported interpreter; corpora that need newer syntax
skip on older interpreters and are checked there to be `syntax_error`.

### 4. Re-index on each workspace revision

- `tests/unit/test_indexing_service.py::test_reindexing_records_a_new_revision_each_time`
- `tests/unit/test_indexing_service.py::test_source_digest_is_deterministic_and_sensitive`
- `tests/unit/test_indexing_service.py::test_index_failures_write_nothing`
- `tests/unit/test_indexing_service.py::test_file_at_the_byte_limit_is_indexed_and_one_more_byte_is_too_large`
- `tests/unit/test_indexing_service.py::test_allow_empty_records_an_empty_revision`
- `tests/unit/test_indexing_service.py::test_concurrent_modification_propagates`
- `tests/contract/test_symbol_index_end_to_end.py::test_unchanged_tree_reindex_gives_identical_digest_and_fingerprints`

### 5. Stale on edit

- `tests/unit/test_symbol_lineage.py::test_content_changed`
- `tests/unit/test_symbol_lineage.py::test_relocated_and_changed`
- `tests/unit/test_symbol_lineage.py::test_rename_then_edit_is_stale_relocated`
- `tests/unit/test_symbol_lineage.py::test_edit_then_revert_is_current`
- `tests/unit/test_provenance_inspection.py::test_traces_carry_reasons_for_every_complete_project_link`
- `tests/unit/test_provenance_exports.py::test_exports_of_an_indexed_project_validate_against_v1`
- `tests/contract/test_symbol_index_end_to_end.py::test_reformat_comments_and_docstring_keep_links_current`
- `tests/contract/test_symbol_index_end_to_end.py::test_editing_the_body_marks_the_link_stale`
- `tests/contract/test_symbol_index_end_to_end.py::test_rename_then_edit_is_stale_at_new_location`

### 6. Orphaned on removal

- `tests/unit/test_symbol_lineage.py::test_removed`
- `tests/unit/test_symbol_lineage.py::test_ambiguous_relocation`
- `tests/unit/test_symbol_lineage.py::test_candidates_are_capped`
- `tests/unit/test_symbol_lineage.py::test_rename_and_edit_in_one_revision_is_removed`
- `tests/unit/test_symbol_lineage.py::test_symbol_from_an_issue_file_that_never_returns_is_removed`
- `tests/unit/test_provenance_inspection.py::test_a_reused_name_does_not_inherit_an_orphaned_link`
- `tests/contract/test_provenance_api.py::test_lineage_fields_for_algorithm_change_and_ambiguous_relocation`
- `tests/contract/test_symbol_index_end_to_end.py::test_deleting_the_function_orphans_the_link`

### 7. Rename without a body change is a move

- `tests/unit/test_symbol_lineage.py::test_relocated`
- `tests/unit/test_symbol_lineage.py::test_rename_chain_follows_to_last`
- `tests/unit/test_symbol_lineage.py::test_file_move_under_the_same_name_is_moved`
- `tests/unit/test_symbol_lineage.py::test_move_into_class_same_file_is_moved_when_identical`
- `tests/unit/test_symbol_lineage.py::test_rename_and_file_move_in_one_step_is_removed`
- `tests/unit/test_symbol_lineage.py::test_preexisting_twin_is_never_a_target`
- `tests/unit/test_symbol_lineage.py::test_two_new_candidates_are_ambiguous`
- `tests/unit/test_symbol_lineage.py::test_one_candidate_with_a_rival_is_ambiguous`
- `tests/unit/test_symbol_lineage.py::test_new_symbol_reusing_a_renamed_name_does_not_inherit`
- `tests/unit/test_symbol_lineage.py::test_move_while_the_source_file_is_unparseable_is_a_move`
- `tests/unit/test_symbol_lineage.py::test_move_while_the_source_file_is_unparseable_still_respects_rivals`
- `tests/unit/test_symbol_lineage.py::test_a_symbol_that_existed_before_the_window_is_not_a_target`
- `tests/unit/test_symbol_lineage.py::test_a_twin_that_left_and_returned_inside_the_window_is_no_rival`
- `tests/unit/test_symbol_lineage.py::test_inherited_twin_is_never_a_rival`
- `tests/unit/test_symbol_lineage.py::test_fingerprints_of_different_algorithms_never_relocate`
- `tests/unit/test_symbol_lineage.py::test_candidates_and_rivals_only_share_the_algorithm`
- `tests/unit/test_symbol_lineage.py::test_m1_fixture_still_gives_current_stale_moved_and_orphaned`
- `tests/unit/test_provenance_inspection.py::test_moved_symbol_shows_the_carried_link`
- `tests/unit/test_provenance_inspection.py::test_list_symbols_worst_freshness_and_decision_count`
- `tests/contract/test_symbol_index_end_to_end.py::test_rename_without_body_change_is_a_move`
- `tests/contract/test_symbol_index_end_to_end.py::test_move_to_another_file_is_a_move`

### 8. Unparseable files are `unknown`, not `orphaned`

- `tests/unit/test_symbol_lineage.py::test_file_not_parsed`
- `tests/unit/test_symbol_lineage.py::test_file_issue_carries_symbols_and_reports_file_not_parsed`
- `tests/unit/test_symbol_lineage.py::test_recovery_after_file_issue_is_not_treated_as_new`
- `tests/unit/test_symbol_lineage.py::test_algorithm_change_is_unknown`
- `tests/unit/test_symbol_lineage.py::test_not_fingerprinted`
- `tests/unit/test_symbol_lineage.py::test_not_indexed`
- `tests/unit/test_symbol_lineage.py::test_unindexed_revisions_attach_by_key_only`
- `tests/unit/test_symbol_lineage.py::test_unindexed_origin_in_an_unparseable_file_is_file_not_parsed`
- `tests/unit/test_symbol_lineage.py::test_m1_unindexed_origin_whose_file_fails_the_first_index_is_file_not_parsed`
- `tests/unit/test_provenance_inspection.py::test_file_issue_on_inspection`
- `tests/contract/test_provenance_api.py::test_file_not_parsed_reports_the_file_issue`
- `tests/unit/test_python_symbols.py::test_unsupported_syntax_is_a_whole_file_issue`
- `tests/unit/test_provenance_graph.py::test_symbols_never_lie_in_a_file_their_revision_lists_as_not_indexed`
- `tests/contract/test_symbol_index_end_to_end.py::test_syntax_error_is_unknown_and_recovers`
- `tests/contract/test_symbol_index_end_to_end.py::test_symlinked_or_oversized_file_is_unknown_not_orphaned`

Lineage soundness over generated histories:

- `tests/unit/test_symbol_lineage.py::test_every_reason_maps_to_a_freshness`
- `tests/unit/test_symbol_lineage.py::test_trace_invariants_reject_inconsistent_combinations`
- `tests/unit/test_symbol_lineage.py::test_related_is_symmetric`
- `tests/unit/test_symbol_lineage.py::test_random_histories_are_sound` (property)
- `tests/unit/test_symbol_lineage.py::test_results_invariant_under_id_permutation` (property)
- `tests/unit/test_symbol_lineage.py::test_generated_histories_reach_relocations_rivals_and_carried_twins`

Generated revisions apply one to three operations each, so a revision can carry an
issue file forward and relocate a symbol elsewhere at the same time; the reach test
asserts that the generator produces every lineage reason, rivals included.

### 9. Persistence and migration

- `tests/contract/test_provenance_migrations.py::test_0002_adds_the_symbol_index_columns_and_nothing_else`
- `tests/contract/test_provenance_migrations.py::test_0001_database_upgrades_and_loads_identically`
- `tests/contract/test_provenance_migrations.py::test_downgrade_to_0001_and_back_keeps_the_m1_rows`
- `tests/contract/test_provenance_migrations.py::test_0002_is_self_contained_and_spells_out_its_enum_values`
- `tests/contract/test_provenance_migrations.py::test_upgraded_schema_matches_the_orm_metadata`
- `tests/contract/test_provenance_migrations.py::test_there_is_exactly_one_head_and_revision_ids_are_four_digits`
- `tests/contract/test_provenance_persistence.py::test_symbol_index_fields_round_trip_through_sqlite_and_memory`
- `tests/contract/test_provenance_persistence.py::test_file_issues_are_stored_as_a_json_list_of_path_and_kind`
- `tests/contract/test_provenance_persistence.py::test_tampered_file_issues_fail_the_load`
- `tests/contract/test_provenance_persistence.py::test_tampered_symbol_index_columns_fail_the_load`
- `tests/contract/test_provenance_persistence.py::test_replayed_scripts_load_identically_from_sqlite_and_memory` (property)
- `tests/security/test_provenance_store_security.py::test_check_constraints_reject_bad_fingerprint_algorithms`
- `tests/security/test_provenance_store_security.py::test_check_constraint_rejects_a_source_digest_on_an_unindexed_revision`
- `tests/security/test_provenance_store_security.py::test_symbol_index_columns_are_append_only`
- `tests/unit/test_provenance_records.py::test_revision_file_issue_rules`
- `tests/unit/test_provenance_records.py::test_revision_source_digest_and_unindexed_rules`
- `tests/unit/test_provenance_records.py::test_file_issue_rules`
- `tests/contract/test_symbol_index_end_to_end.py::test_reopened_store_gives_identical_traces_and_api_responses`

The export contracts are unchanged; the M1 export goldens and schema locks still pass:

- `tests/unit/test_provenance_exports.py::test_demo_exports_match_the_golden_bytes`
- `tests/contract/test_export_schemas.py::test_schema_file_hash_matches_the_released_lock`
- `tests/unit/test_provenance_exports.py::test_exports_of_an_indexed_project_validate_against_v1`

### 10. API (additive fields only)

- `tests/contract/test_provenance_api.py::test_demo_symbols_to_inspection_round_trip`
- `tests/contract/test_provenance_api.py::test_complete_project_symbols_listing`
- `tests/contract/test_provenance_api.py::test_complete_project_inspection_key_sets_and_enum_values`
- `tests/contract/test_provenance_api.py::test_complete_project_test_and_review_details`
- `tests/contract/test_provenance_api.py::test_lineage_fields_for_algorithm_change_and_ambiguous_relocation`
- `tests/contract/test_provenance_api.py::test_file_not_parsed_reports_the_file_issue`
- `tests/contract/test_provenance_api.py::test_symbol_index_adds_no_route_and_no_write_method`
- `tests/contract/test_provenance_api.py::test_new_operations_are_listed_as_get_only_api_routes`
- `tests/contract/test_provenance_api.py::test_validation_errors_match_the_published_openapi_schema`
- `tests/unit/test_provenance_inspection.py::test_link_health_order`
- `tests/unit/test_provenance_inspection.py::test_link_health_is_empty_without_links`
- `tests/contract/test_legacy_trace.py::test_legacy_trace_matches_the_golden_file` (unchanged)
- `tests/contract/test_symbol_index_end_to_end.py::test_api_responses_never_contain_source_text`

### 11. Security boundary

Each rule of the workspace trust boundary (ADR 0039, section 2.4) and the tests that
prove it. Every test listed here is a negative or boundary test.

**S1. Indexed code is never executed, imported or compiled.**

- `tests/security/test_python_extractor_security.py::test_indexed_code_is_never_executed`
- `tests/security/test_workspace_reader_security.py::test_reading_never_executes_the_workspace`
- `tests/architecture/test_dependencies.py::test_indexing_adapters_never_import_execution_or_network_modules`
- `tests/architecture/test_dependencies.py::test_indexing_adapters_never_execute_compile_or_import_code`
- `tests/architecture/test_dependencies.py::test_guards_detect_violations`

**S2. Source decoding uses the extractor's own allowlist; cookie names never reach
`codecs.lookup`.**

- `tests/security/test_python_extractor_security.py::test_cookie_names_never_reach_codecs_lookup`
- `tests/unit/test_python_symbols.py::test_cookie_decoder_agrees_with_tokenize_on_allowlisted_names`
- `tests/unit/test_python_symbols.py::test_unsupported_encodings`
- `tests/unit/test_python_symbols.py::test_utf8_bom_and_cookies_decode`
- `tests/unit/test_python_symbols.py::test_decode_errors`
- `tests/unit/test_python_symbols.py::test_nul_is_binary`
- `tests/architecture/test_dependencies.py::test_python_extractor_never_touches_files_or_codecs`

**S3. The extractor never raises, is bounded, and its result does not depend on the
warnings filter, the `int` digit limit, the recursion limit or the caller's stack
depth.**

- `tests/unit/test_python_symbols.py::test_extract_never_raises_on_arbitrary_bytes` (property)
- `tests/unit/test_python_symbols.py::test_extract_never_raises_on_python_like_text` (property)
- `tests/unit/test_python_symbols.py::test_symbol_and_node_limits_give_too_complex`
- `tests/security/test_python_extractor_security.py::test_pathological_nesting_is_too_complex_or_syntax_error_within_2s`
- `tests/security/test_python_extractor_security.py::test_result_is_identical_under_warnings_error`
- `tests/security/test_python_extractor_security.py::test_result_does_not_depend_on_the_callers_stack_depth`
- `tests/security/test_python_extractor_security.py::test_nesting_deeper_than_the_bound_is_too_complex_on_every_interpreter`
- `tests/security/test_python_extractor_security.py::test_result_does_not_depend_on_the_int_digit_limit`
- `tests/security/test_python_extractor_security.py::test_result_does_not_depend_on_a_lowered_recursion_limit`
- `tests/security/test_python_extractor_security.py::test_unexpected_parser_errors_propagate_to_the_caller`

**S4. The reader never follows a symlink, also after a swap between listing and
opening.**

- `tests/security/test_workspace_reader_security.py::test_symlinked_file_to_an_outside_secret_is_reported_and_never_read`
- `tests/security/test_workspace_reader_security.py::test_symlinked_directory_is_never_followed`
- `tests/security/test_workspace_reader_security.py::test_a_file_swapped_for_a_symlink_after_listing_is_reported_and_never_read`
- `tests/security/test_workspace_reader_security.py::test_a_directory_swapped_for_a_symlink_after_listing_is_skipped`
- `tests/security/test_workspace_reader_security.py::test_a_symlink_candidate_counts_toward_max_files`
- `tests/security/test_workspace_reader_security.py::test_a_symlinked_root_is_allowed_because_the_caller_chose_it`
- `tests/contract/test_symbol_index_end_to_end.py::test_symlinked_or_oversized_file_is_unknown_not_orphaned`

**S5. The reader never blocks: special files are `not_regular` and never read.**

- `tests/security/test_workspace_reader_security.py::test_fifo_and_unix_socket_named_py_are_not_regular_and_never_block`
- `tests/security/test_workspace_reader_security.py::test_a_fifo_swapped_in_after_listing_is_opened_non_blocking_and_not_read`
- `tests/security/test_workspace_reader_security.py::test_a_socket_swapped_in_after_listing_is_not_regular`
- `tests/security/test_workspace_reader_security.py::test_open_errors_that_mean_a_socket_are_not_regular`
  (`ENXIO` on Linux, `EOPNOTSUPP` on macOS)

**S6. Reads are bounded per file and per run.**

- `tests/security/test_workspace_reader_security.py::test_an_oversized_file_is_too_large_and_never_read`
- `tests/security/test_workspace_reader_security.py::test_a_file_growing_during_the_read_is_too_large_and_reads_are_bounded`
- `tests/security/test_workspace_reader_security.py::test_a_file_at_the_byte_limit_is_read_whole`
- `tests/security/test_workspace_reader_security.py::test_limits_are_inclusive`

**S7. Every run limit fails closed, writes nothing, echoes no path and leaks no
descriptor.**

- `tests/security/test_workspace_reader_security.py::test_every_limit_fails_closed_without_paths_or_leaked_descriptors`
- `tests/security/test_workspace_reader_security.py::test_successful_reads_leave_no_open_descriptors`
- `tests/unit/test_indexing_service.py::test_index_failures_write_nothing`
- `tests/unit/test_index_preview_cli.py::test_a_limit_error_exits_2_with_a_fixed_message`

**S8. An unreadable subtree fails closed instead of looking deleted; an unreadable
file is `unreadable`.**

- `tests/security/test_workspace_reader_security.py::test_an_unreadable_directory_fails_closed`
- `tests/security/test_workspace_reader_security.py::test_a_directory_that_cannot_be_opened_fails_closed`
- `tests/security/test_workspace_reader_security.py::test_a_directory_that_cannot_be_listed_fails_closed`
- `tests/security/test_workspace_reader_security.py::test_an_entry_whose_type_cannot_be_read_fails_closed`
- `tests/security/test_workspace_reader_security.py::test_a_root_that_cannot_be_listed_is_unavailable`
- `tests/security/test_workspace_reader_security.py::test_an_unreadable_file_is_unreadable`
- `tests/security/test_workspace_reader_security.py::test_a_file_that_cannot_be_opened_is_unreadable`
- `tests/security/test_workspace_reader_security.py::test_a_read_error_makes_the_file_unreadable_and_closes_it`

**S9. Names are validated before anything is opened, at the root and in
subdirectories; rejected names are counted and never echoed.**

- `tests/security/test_workspace_reader_security.py::test_unrepresentable_file_names_are_counted_and_never_echoed`
- `tests/security/test_workspace_reader_security.py::test_non_utf8_file_names_are_counted_and_never_echoed`
- `tests/security/test_workspace_reader_security.py::test_unrepresentable_directory_names_are_never_entered`
- `tests/security/test_workspace_reader_security.py::test_paths_over_500_characters_are_counted_and_never_echoed`
- `tests/security/test_workspace_reader_security.py::test_invalid_extra_excluded_names_are_rejected_without_echo`
- `tests/security/test_workspace_reader_security.py::test_invalid_suffixes_are_rejected`

**S10. Hidden, tool, virtual-environment and excluded directories are skipped; only
the configured suffixes are read.**

- `tests/security/test_workspace_reader_security.py::test_hidden_tool_and_virtual_environment_directories_are_skipped`
- `tests/security/test_workspace_reader_security.py::test_extra_excluded_directory_names_are_skipped_at_any_depth`
- `tests/security/test_workspace_reader_security.py::test_suffix_matching_is_case_sensitive_and_other_files_are_counted`

**S11. The walk stays on one file system unless asked otherwise.**

- `tests/security/test_workspace_reader_security.py::test_one_file_system_skips_directories_on_another_device`
- `tests/security/test_workspace_reader_security.py::test_crossing_devices_is_allowed_only_when_asked`

**S12. Output paths are relative and deterministic, never absolute or escaping the
root; the root is never echoed.**

- `tests/security/test_workspace_reader_security.py::test_no_output_path_is_absolute_or_escapes_the_root`
- `tests/security/test_workspace_reader_security.py::test_output_order_is_deterministic_by_code_point`
- `tests/security/test_workspace_reader_security.py::test_a_missing_root_is_unavailable_without_echoing_the_path`
- `tests/security/test_workspace_reader_security.py::test_a_non_directory_root_is_unavailable_without_echoing_the_path`
- `tests/unit/test_index_preview_cli.py::test_a_missing_root_exits_2_without_echoing_the_path`

**S13. Source text never leaves the indexer: not in issues, rows, API responses,
exports or CLI output.**

- `tests/security/test_python_extractor_security.py::test_issue_records_never_contain_source_text`
- `tests/unit/test_index_preview_cli.py::test_preview_never_prints_source_text_or_absolute_paths`
- `tests/contract/test_symbol_index_end_to_end.py::test_api_responses_never_contain_source_text`

**S14. The reader is POSIX-only and refuses platforms without fd-relative, no-follow
primitives; the constructor never touches the filesystem.**

- `tests/security/test_workspace_reader_security.py::test_platforms_without_fd_relative_no_follow_primitives_are_refused`
- `tests/security/test_workspace_reader_security.py::test_the_constructor_never_touches_the_filesystem`
- `tests/security/test_workspace_reader_security.py::test_the_reader_satisfies_the_port`

**S15. Hard links are read, as documented (ADR 0039, risks).**

- `tests/security/test_workspace_reader_security.py::test_hard_links_are_read_as_documented`

**S16. Layering: the indexing adapters import only the standard library, the domain and
the application; the domain and the application never parse code or touch files.**

- `tests/architecture/test_dependencies.py::test_indexing_adapters_import_only_stdlib_domain_and_application`
- `tests/architecture/test_dependencies.py::test_domain_and_application_never_parse_code_or_touch_files`
- `tests/architecture/test_dependencies.py::test_domain_and_application_respect_direction`

**S17. No HTTP trigger and no write method; the route allowlist is unchanged.**

- `tests/contract/test_provenance_api.py::test_symbol_index_adds_no_route_and_no_write_method`
- `tests/security/test_oidc_authorization_boundary_security.py::test_only_read_only_foundation_api_routes_are_exposed` (unchanged)
- `tests/security/test_provenance_api_security.py::test_write_methods_are_not_allowed` (unchanged)

**S18. The stored symbol-index columns are constrained and append-only; tampered rows
fail the load.**

- `tests/security/test_provenance_store_security.py::test_check_constraints_reject_bad_fingerprint_algorithms`
- `tests/security/test_provenance_store_security.py::test_check_constraint_rejects_a_source_digest_on_an_unindexed_revision`
- `tests/security/test_provenance_store_security.py::test_symbol_index_columns_are_append_only`
- `tests/security/test_provenance_store_security.py::test_record_rows_cannot_be_updated`
- `tests/contract/test_provenance_persistence.py::test_tampered_file_issues_fail_the_load`
- `tests/contract/test_provenance_persistence.py::test_tampered_symbol_index_columns_fail_the_load`

The preview CLI's other behaviour (usage errors, output format) is covered by the
remaining tests in `tests/unit/test_index_preview_cli.py`.

## Intentional changes to M1 tests

Links attach to symbols by lineage instead of by key (ADR 0039, Consequences), so three
M1 expectations change:

1. `tests/unit/test_provenance_inspection.py::test_list_symbols_worst_freshness_and_decision_count`:
   `calibrate` lists `(1, moved)` instead of `(0, None)`.
2. `tests/unit/test_provenance_inspection.py::test_symbol_without_links_warns_no_linked_decision`
   now uses a new unlinked symbol recorded in a third revision;
   `test_moved_symbol_shows_the_carried_link` covers the moved `calibrate`.
3. `tests/contract/test_provenance_api.py::test_complete_project_symbols_listing`:
   `calibrate` lists `(1, "moved")`.

Other API key-set assertions were extended additively.

## Quality gates

All gates from `CLAUDE.md` must pass before merge:

```bash
uv run ruff check src tests scripts prototypes
uv run ruff format --check src tests scripts prototypes
uv run mypy src
uv run pytest -q --cov=asca --cov-branch --cov-fail-under=85
cd apps/web && npm ci && npm run typecheck && npm run test:run && npm run build
```

The frontend is unchanged in M2, so its gate is expected to pass unchanged. The
fingerprint golden module should also be run on each supported interpreter (3.11, 3.12
and 3.13).

## Open questions

The maintainer questions and their applied defaults are listed in ADR 0039 under
"Open questions for the maintainer".
