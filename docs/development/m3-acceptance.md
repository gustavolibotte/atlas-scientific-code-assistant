# M3 — Federated knowledge layer (public sources first): acceptance

Milestone definition: [`docs/roadmap.md`](../roadmap.md) (M3). Architecture and policy:
[ADR 0040](../adr/0040-federated-knowledge-layer.md). ASCA is not an official ATLAS or
CERN product; authority categories are ASCA project policy.

## Scope

- Application layer (`asca.application.knowledge`): the async `KnowledgeProvider`
  port and its models (`models`, `pids`, `text`), the authority suggestion policy
  `asca-authority/1` (`policy`), the `FederationService` with identity grouping
  (`federation`), and registration planning with an atomic source-and-version write
  (`registration`, `ProvenanceService.record_source_version`).
- Shared infrastructure (`asca.infrastructure.knowledge`): frozen settings
  (`settings`), the bounded httpx2 client and error mapping (`http`), endpoint URL and
  address checks (`url_guard`), and environment-only secrets (`secrets`).
- Adapters: INSPIRE-HEP (`inspire`), arXiv (`arxiv`), HEPData search (`hepdata`), the
  local curated library (`local`), and the generic MCP client (`mcp_client`) with its
  stdio guard (`mcp_stdio_guard`).
- Configuration (`config`): a permission-checked TOML file found through `--config`,
  `ASCA_KNOWLEDGE_CONFIG` or the XDG path, never the working directory.
- Factory (`factory`): `build_federation` builds every configured provider (disabled
  ones are still reported) in the configured precedence.
- CLI (`python -m asca.infrastructure.knowledge`, prog `asca-knowledge`): `search`,
  `fetch`, `health` and `providers`, JSON (default) or text output, wired to
  `build_federation`. Every network call needs `--live`.
- Fixtures: the replay transport, the recorder (`recording`,
  `scripts/record_knowledge_fixtures.py`), recorded and synthetic fixtures under
  `tests/fixtures/knowledge/`, and the network kill switch in `tests/conftest.py`.
- No HTTP route, no frontend change, no export-schema change, no golden regeneration
  outside the new knowledge golden file.

## Exit criteria and the tests that prove them

Test ids are relative to the repository root and run with `uv run pytest -q <id>`.

| Roadmap exit criterion | Tests |
|---|---|
| One query returns normalized evidence from at least two providers | `tests/contract/test_knowledge_federation_end_to_end.py::test_one_query_returns_deduplicated_evidence_from_several_providers_and_reports_the_failure` (recorded INSPIRE, arXiv and HEPData exchanges plus a synthetic local note; CLI JSON byte-identical to the golden), `tests/contract/test_knowledge_federation_end_to_end.py::test_the_exit_run_is_deterministic_under_shuffling_and_delays` (20 seeded runs) |
| An unavailable provider is reported, not hidden | the same test (HEPData reported `failed`, `blocked/bot_challenge`, status 403; `complete` false; "Sources not consulted" in text output via `tests/contract/test_knowledge_cli.py::test_exit_run_in_text_format_names_the_sources_not_consulted`), plus `tests/contract/test_knowledge_federation_end_to_end.py::test_unavailable_provider_variants` (arXiv 503, a provider stopped by the federation deadline, a stdio MCP server that exits at once) and `tests/unit/test_federation.py::test_search_reports_every_provider_and_assesses_members` |
| Registration and claim check from fetched text (M4 path) | `tests/contract/test_knowledge_federation_end_to_end.py::test_registration_and_claim_check_from_fetched_text` (INSPIRE and arXiv records on one Source with two versions; quote check `source_text_checked`, a wrong quote `mismatch`; idempotent re-registration) |
| De-duplication by DOI, arXiv id, INSPIRE record and CDS report number | `tests/unit/test_federation.py` grouping tests: `test_candidates_sharing_an_arxiv_id_merge_without_fusing_fields`, `test_related_pids_never_merge`, `test_two_inspire_records_through_one_doi_are_split_and_flagged`, `test_same_provider_collision_is_split`, `test_two_arxiv_identities_split_and_unique_keys_survive`, `test_multiple_dois_flag_keeps_the_merge`, `test_access_mixed_and_effective_access`, `test_key_precedence`, `test_groups_are_ordered_by_best_rank_precedence_and_key`, `test_grouping_is_permutation_invariant_conservative_and_idempotent` (property) |
| CI uses recorded fixtures; live provider tests are opt-in and never run in CI | `tests/contract/test_knowledge_fixtures.py`, `tests/contract/test_knowledge_federation_end_to_end.py::test_the_exit_helper_refuses_synthetic_fixtures`, `tests/contract/test_knowledge_federation_end_to_end.py::test_without_live_the_exit_run_sends_no_request`, `tests/security/test_knowledge_network_guard_security.py`, `tests/ci/test_workflow_policy.py::test_live_provider_tests_never_run_in_ci`; opt-in checks in `tests/contract/test_knowledge_live.py` (skipped unless `ASCA_LIVE=1`) |

### Local curated library

- `tests/contract/test_local_library.py::test_fixture_library_maps_the_internal_note`
- `tests/contract/test_local_library.py::test_fetch_returns_the_exact_file_text`
- `tests/contract/test_local_library.py::test_fetch_keeps_text_unnormalised`
- `tests/contract/test_local_library.py::test_provider_contract`
- `tests/contract/test_local_library.py::test_unlisted_files_are_ignored`
- `tests/contract/test_local_library.py::test_scoring_and_order`
- `tests/contract/test_local_library.py::test_unusable_listed_documents_are_dropped`
- `tests/contract/test_local_library.py::test_missing_manifest_is_not_configured`
- `tests/contract/test_local_library.py::test_invalid_manifests_are_refused` (extra key,
  missing `access_class`, duplicate path, bad suffix and 26 more cases)
- `tests/contract/test_local_library.py::test_published_hint_and_report_numbers`

### Configuration

- `tests/contract/test_knowledge_config.py::test_defaults_when_the_default_file_is_absent`
- `tests/contract/test_knowledge_config.py::test_full_example_parses`
- `tests/contract/test_knowledge_config.py::test_precedence_validation`
- `tests/contract/test_knowledge_config.py::test_stdio_keys_are_forbidden_on_http`
- `tests/contract/test_knowledge_config.py::test_http_keys_are_forbidden_on_stdio`
- `tests/contract/test_knowledge_config.py::test_arxiv_min_interval_below_three_seconds_is_refused`
- `tests/contract/test_knowledge_config.py::test_mcp_ceiling_above_working_material_is_refused`
- `tests/contract/test_knowledge_config.py::test_explicit_missing_path_is_an_error`

### CLI

- `tests/contract/test_knowledge_cli.py::test_search_json_format_and_exit_zero`
- `tests/contract/test_knowledge_cli.py::test_without_live_network_providers_are_never_called`
  (no provider call, `live_disabled`, exit 4)
- `tests/contract/test_knowledge_cli.py::test_exit_three_when_some_providers_fail`
- `tests/contract/test_knowledge_cli.py::test_usage_errors_exit_two_without_echo`
- `tests/contract/test_knowledge_cli.py::test_fetch_prints_no_text_without_print_text`
- `tests/contract/test_knowledge_cli.py::test_providers_shows_secret_names_never_values`
- `tests/contract/test_knowledge_cli.py::test_text_format_escapes_controls`
- `tests/contract/test_knowledge_cli.py::test_default_build_uses_the_factory_and_stays_offline_without_live`
- `tests/contract/test_knowledge_cli.py::test_search_live_over_replay_matches_the_exit_golden`
  (the real factory over replay; golden `tests/contract/golden/knowledge_search_exit.json`,
  regenerated only with `uv run python tests/support/knowledge_exit.py --write-golden`
  after a reviewed re-recording)
- `tests/contract/test_knowledge_cli.py::test_search_without_live_sends_no_request_over_the_real_factory`
- `tests/contract/test_knowledge_cli.py::test_exit_run_in_text_format_names_the_sources_not_consulted`

### Adapters

- `tests/contract/test_inspire_adapter.py`, `tests/contract/test_arxiv_adapter.py`,
  `tests/contract/test_hepdata_adapter.py`, `tests/contract/test_mcp_adapter.py`; each
  runs `knowledge_contract.assert_provider_contract`.

### Policy and registration

- `tests/unit/test_knowledge_policy.py` (A only for refereed INSPIRE with a curated
  non-HEPData DOI and public access; arXiv is D; never B or C, property tested).
- `tests/unit/test_knowledge_registration.py` (every refusal code, primary PID order,
  reuse through an identity PID, the `authority_basis` template, the atomic
  `record_source_version`).

## Security negative tests

Every rule below has explicit negative tests marked `security`.

| File | What it proves |
|---|---|
| `tests/security/test_knowledge_http_security.py` | byte caps before and while reading; compressed responses refused; `identity` always requested; redirects refused and Location never requested; no cookie replay; no `.netrc` credentials; proxy selection; TLS verification always on; strict JSON; the interval gate never releases early after an early wake-up and bounds its extra sleeps |
| `tests/security/test_knowledge_url_guard_security.py` | http only for loopback with the flag; userinfo, query, fragment and bad ports refused; link-local (cloud metadata), multicast, unspecified and reserved always refused; private ranges and loopback need flags; a mixed DNS answer is refused; messages never contain the URL |
| `tests/security/test_knowledge_secrets_security.py` | `RedactedSecret` never prints, formats or pickles; `ASCA_` variable names only; tokens with CR/LF or too short refused; an MCP canary token never leaks from the client or from the CLI's stdout, stderr and logs (success and 401); echoed tokens are redacted; the bearer never leaves the configured origin |
| `tests/security/test_knowledge_config_security.py` | group- or world-writable, foreign-owned, symlinked or oversized configuration refused; group-writable directory with a stdio server refused; inline `token`/`password` refused without echo; `token_env = "GITHUB_TOKEN"`, env source `HOME`, `LD_PRELOAD`, relative, writable or non-executable commands, and unsafe URLs refused; the default path is never the working directory |
| `tests/security/test_knowledge_xml_security.py` | billion laughs, XXE (file and http), external DTD, parameter entities and quadratic blowup are `invalid_xml` with no additional request; at most 25 entries; oversized feeds refused |
| `tests/security/test_mcp_isolation_security.py` | scrubbed child environment and private working directory; output limits kill the server; only configured tools are called; sampling and elicitation refused; MCP access claims can only restrict |
| `tests/security/test_knowledge_injection_as_data.py` | hostile titles and snippets come back cleaned as data, through the adapters and through the federation and CLI (text and JSON); terminal output has no escape byte; titles are prefixed `provider data:`; landing and snippet URLs are never fetched; no subprocess |
| `tests/security/test_knowledge_egress_security.py` | an internal query sends zero requests to public providers, at adapter and federation level; an internal local document's title and text never appear in any outbound request; the recorder refuses non-public providers and free-form URLs |
| `tests/security/test_knowledge_network_guard_security.py` | the kill switch blocks internet connections and lookups, allows loopback; `CI` with `ASCA_LIVE` refused |
| `tests/architecture/test_dependencies.py` | import allowlists for the adapters; no `httpx` in `src`; declared third-party imports only; XML only through `defusedxml`; no code execution; no credential fields in application types; the CLI never prompts |

## How to run

Without `--live`, no request is sent: network providers are reported as
`skipped`/`live_disabled` and the CLI prints `note: network providers need --live`.

```bash
uv run python -m asca.infrastructure.knowledge providers
uv run python -m asca.infrastructure.knowledge search \
    "energy reconstruction liquid argon calorimeter neural network" --live
uv run python -m asca.infrastructure.knowledge search "optimal filtering" \
    --providers local --query-class internal --format text
uv run python -m asca.infrastructure.knowledge fetch inspire 1920956 --live --print-text
uv run python -m asca.infrastructure.knowledge health --live --deep
```

Exit codes: `search` 0 when every selected provider is OK, 3 when some are, 4 when none
is; `fetch` 0 or 4; `health` 0 when every provider is available or not probed, else 3;
2 for any usage or configuration error.

A minimal configuration (`~/.config/asca/knowledge.toml`, mode 0600):

```toml
format = "asca-knowledge/1"
[providers.local]
enabled = true
root = "~/asca-library"
```

The library root holds a `manifest.toml` (`format = "asca-library/1"`) listing each
document with its path, title, version, access class (required) and authority hint;
see `tests/fixtures/knowledge/local/` for a synthetic example.

Recording fixtures (maintainer only, never in CI; review the diff before committing):

```bash
uv run python scripts/record_knowledge_fixtures.py --live [--scenario NAME ...] [--force]
```

Live tests (never in CI; the suite refuses `CI` together with `ASCA_LIVE`):

```bash
ASCA_LIVE=1 uv run pytest -q -m live tests/contract/test_knowledge_live.py
```

They check structure only: INSPIRE `arxiv:0912.2642` is record 840027 with DOI
`10.1140/epjc/s10052-010-1354-y`; arXiv fetch `0912.2642` is v4 with the same DOI and
two arXiv requests are at least 3 s apart; HEPData answers OK or `blocked`; a federated
INSPIRE plus arXiv search returns a group with members from both. Run once from the
integration container on 2026-11-14 for INSPIRE and arXiv only (HEPData deselected):
the first run found the arXiv spacing at 2.9986 s (an event-loop early wake-up in the
interval gate), the gate was fixed and covered by a negative test, and the second run
passed (3 passed, 1 deselected). About ten live requests were sent in total.

## Fixtures and licences

- Recorded fixtures: INSPIRE and arXiv exit-query search and fetch, the arXiv unknown-id
  feed, and the real HEPData 403 challenge. Only CC0 metadata is kept (ids, titles,
  DOIs, dates, at most three author names); abstracts are replaced with a synthetic
  sentence; emails, ORCIDs and affiliations are never kept.
- Synthetic fixtures are flagged `synthetic: true`: rate limiting, 503, the arXiv error
  entry, the provisional HEPData search, hostile payloads, and the local library.
- `tests/contract/test_knowledge_fixtures.py` checks the format, licence fields, hashes,
  header allowlist, size limits and forbidden patterns of every committed fixture.

## Known limits

- **HEPData**: search currently returns a Cloudflare challenge from this environment,
  reported as `blocked/bot_challenge` and never evaded. The search schema is
  provisional (from the hepdata-cli source) and record fetch is unsupported until the
  maintainer records fixtures.
- **No HTTP route**: the knowledge layer is CLI-only in M3 (ADR 0040, section 8).
- **stdio MCP servers are not sandboxed**: the guard bounds resources and output only.
- **DNS rebinding (TOCTOU)**: MCP addresses are checked before each session, not at
  connect time.
- **Local library reads run in a worker thread**: a hung filesystem read times out on
  time, but the process exits only when the read returns.
- No retries, no pagination beyond page 1, no cache, no CLI `register`.

## Quality gates

All gates from `CLAUDE.md` must pass before merge:

```bash
uv run ruff check src tests scripts prototypes
uv run ruff format --check src tests scripts prototypes
uv run mypy src
uv run pytest -q --cov=asca --cov-branch --cov-fail-under=85
cd apps/web && npm ci && npm run typecheck && npm run test:run && npm run build
```

The frontend is unchanged in M3, so its gate is expected to pass unchanged.

## Open questions

The maintainer questions and their applied defaults are listed in ADR 0040 under
"Open questions for the maintainer".
