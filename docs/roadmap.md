# Roadmap v2 — evidence-to-code first

> Status: **accepted** in [ADR 0037](adr/0037-prioritize-evidence-to-code-vertical-slice.md).
> Roadmap v1 (identity before knowledge) is preserved in Git history.

## Product goal

A local-first application (macOS, Linux, later hosted) in which a researcher asks for
scientific code and receives a working project whose **important decisions are
traceable** to identifiable sources, implemented symbols and executed tests:

```text
Function ──implements──> Decision ──supported_by──> Claim ──located_in──> Source@version
    │                        │
    └──verified_by──> Test ──recorded_in──> ValidationRun (environment snapshot)
```

Selecting a function in the UI must show the decisions behind it, where their support
was found, which tests verify it, and whether any link is stale.

## Guiding rules

1. **Vertical slices.** Every milestone ships running behaviour plus tests, not only
   specifications.
2. **chATLAS-first, never chATLAS-only.** The application works with public sources
   and degrades explicitly ("sources not consulted") when a provider is unavailable.
3. **Honest provenance.** No fabricated citations. A decision without support is
   recorded as `unsupported`; agreement between conflicting sources is not invented.
4. **Data governance by access class.** Evidence marked `internal` or `restricted` is
   processed only by models approved for that class (local Ollama by default).
5. **Hexagonal boundaries.** Domain and application layers never import web
   frameworks, HTTP clients, databases, MCP or LLM SDKs (enforced by
   `tests/architecture`).

## Completed

| Milestone | Content |
|---|---|
| Phase 0 | FastAPI, React shell, synthetic provenance viewer, CI matrix, architecture tests |
| Phase 1A (frozen) | CERN native OIDC (PKCE, JWKS, JWS, claims, role observation), web authorization contracts C2–C9 |

## Milestones

Each milestone ends with one acceptance document in `docs/development/` and green
`Backend quality gate` and `Frontend quality gate` checks.

### M1 — Persisted evidence and provenance core

- Extend the domain model: `Source`, `SourceVersion` (content hash, retrieval time,
  access class, authority), `Claim` (quote, locator, verification state),
  `ScientificDecision` (status `proposed | supported | unsupported | conflicting |
  approved | rejected`, alternatives, assumptions), `CodeSymbol`, `TestCase`,
  `ValidationRun`, `Approval`, `EnvironmentSnapshot`.
- Invariants: `approved` requires an `Approval`; `published` authority requires a real
  source with a persistent identifier; a `supported` decision needs at least one
  `source_text_checked` claim.
- Persistence: SQLAlchemy 2 + Alembic on SQLite behind repository ports; PostgreSQL
  compatibility verified in CI later.
- Versioned JSON Schemas for exported artifacts: `evidence_manifest.json`,
  `decision_records.json`, `validation_report.json`.
- **Exit:** create, persist, reload and export a complete trace; property tests for
  invariants; the API serves a stored trace instead of the in-code fixture.

### M2 — Code symbol index and link staleness

- Python symbol extraction with `ast`: qualified name, span, and a fingerprint of the
  normalized AST (insensitive to formatting and comments).
- Re-index on each workspace revision; mark decision-symbol links `stale` when the
  fingerprint changes, and `orphaned` when the symbol disappears.
- Tree-sitter adapter later for C++ (M9).
- **Exit:** editing a function body marks its links stale; renaming without body
  change is detected as a move.

### M3 — Federated knowledge layer (public sources first)

- Extend the `KnowledgeProvider` port: `search`, `fetch`, `health`; candidates carry
  provider, access class, authority, version and locator.
- Adapters: INSPIRE-HEP REST, arXiv, HEPData, local curated documents.
- Generic MCP client adapter (official `mcp` SDK, streamable HTTP and stdio) to
  reach chATLAS and tool servers such as `cerngitlab-mcp`. AGPL-licensed servers
  run as separate processes and are never imported.
- Federation service with timeouts, partial-failure reporting and de-duplication by
  persistent identifier (DOI, arXiv ID, INSPIRE record, CDS report number).
- CI uses recorded fixtures; live provider tests are opt-in and never run in CI.
- **Exit:** one query returns normalized evidence from at least two providers; an
  unavailable provider is reported, not hidden.

### M3b — chATLAS access probe (runs on the maintainer's Mac)

- Read-only diagnostic: transport reachability, authorization requirement, tool
  discovery, one test query. Never automate the web login or extract browser cookies.
- The outcome selects scenario **A** (MCP usable), **B** (web only: chATLAS used for
  comparison) or **C** (not reachable: rely on public sources). Record it in an ADR.

### M4 — Language-model port and scientific planner

- `LanguageModel` port with structured output validated by Pydantic. Adapters:
  Ollama (local) and Anthropic Claude API. A routing policy maps evidence access
  class to permitted models.
- Planner pipeline with persisted steps: requirement analysis → sub-question
  retrieval → scientific specification (equations, units, assumptions, validity) →
  decision table → test plan.
- Citation verifier: a claim is `source_text_checked` only if its quote is found in
  the fetched source text; otherwise it is downgraded and flagged.
- **Exit:** for Experiment B, produce an auditable plan where every decision is
  either supported by verified claims or explicitly unsupported. No code yet.

### M5 — Code generation in an isolated workspace

- One Git repository per project workspace; agent tools restricted to read, write
  and patch inside it, mediated by a policy layer (no shell access for the model).
- Generated layout: `src/`, `tests/`, `environment.yml` or `pyproject.toml`,
  `README.md`, `scientific_plan.json`, `evidence_manifest.json`,
  `decision_records.json`.
- Decision-to-symbol links are created from the M2 index, never from model claims
  alone.
- **Exit:** Experiment B project is generated, passes `ruff` and static checks, and
  every decision resolves to at least one symbol or is marked unimplemented.

### M6 — Isolated execution and validation

- Separate runner process; container backend (Docker/Podman on Linux, a supported
  container runtime on macOS) with CPU, memory, time, disk limits and no network by
  default. A Conda environment is not treated as a sandbox.
- `ValidationRun` records command, exit status, test results, artifacts and an
  environment snapshot. Bounded self-repair loop (configurable, default 3 attempts).
- Scientific test templates: analytic reference case, invariants (property-based),
  noise robustness, reproducibility with fixed seeds.
- **Exit:** reproducible validation report for Experiment B; failures are recorded,
  never hidden.

### M7 — Scientific workspace UI

- Conversation with streamed agent state (server-sent events), plan review and
  approval, file tree and editor, **Function Inspector**, Evidence Explorer,
  validation panel, diff view between revisions.
- Playwright end-to-end tests with recorded backends.
- **Exit:** the whole M4–M6 flow is completed from the browser.

### M8 — Evaluation harness

- 20–30 benchmark tasks with expert-selected sources and acceptance properties,
  including adversarial cases (contradictory sources, obsolete APIs, missing
  parameters, unit mismatches, unsupported requests).
- Metrics: Recall@k and MRR, grounding rate, test pass rate, provenance
  completeness, unauthorized-action block rate. Reuse ideas from
  `chATLAS_Benchmark` (Apache-2.0).
- **Exit:** benchmark runs nightly with recorded fixtures and reports trends.

### M9 — ROOT, statistics, C++ and Linux executors

- `uproot`, `awkward`, `hist`, `pyhf`; optional PyROOT; C++ symbol indexing via
  Tree-sitter; remote Linux executor for ATLAS software environments. Code that runs
  on macOS is never described as Athena/AnalysisBase compatible.
- **Exit:** Experiment A (ROOT analysis) completed end to end.

### M10 — Desktop and hosted deployment

- Tauri 2 desktop shell with restricted capabilities.
- Hosted mode: resume the frozen web authorization track (BFF, server-side sessions,
  G1–G10), PostgreSQL, multi-user isolation, remote execution workers.
- **Exit:** reproducible signed builds; hosted deployment reviewed against the
  security model.

## Reference experiments

- **Experiment B (first):** compare linear amplitude estimators for calorimeter
  pulses with correlated noise and pedestal variation; analytic tests and benchmark
  figures. Tests the core differentiator: literature-grounded algorithmic decisions.
- **Experiment A (M9):** read ROOT events or histograms, apply a documented
  selection, compute distributions and uncertainties, produce comparison plots.
