# ATLAS Scientific Code Assistant (ASCA)

> **Foundation release — Phase 0.** This is an independently developed scientific coding
> assistant. It is **not** an official ATLAS or CERN product and does not claim collaboration approval.

An evidence-first scientific software engineering platform. The intended product will connect
knowledge sources, scientific decisions, code symbols, and validation results. In this foundation
release, all external integrations, CERN SSO, code generation, and code execution are explicitly
**unavailable**. The trace viewer displays **synthetic demonstration data** only.

## Requirements

- macOS or Linux with Python 3.11–3.13 and [`uv`](https://docs.astral.sh/uv/).
- Node.js 22 and npm for the web UI.
- No connection to the previous `atlas-rag` project is required.

## First-time installation

```bash
bash scripts/bootstrap.sh
```

The bootstrap generates `uv.lock` and `apps/web/package-lock.json` on your computer.
**Commit both lockfiles** to the new private repository before enabling CI; they cannot
be pre-generated in an offline build environment. Never commit `.env` or tokens.

## Start the API

```bash
uv sync --all-groups
uv run uvicorn asca.api.main:create_app_from_environment --factory --host 127.0.0.1 --port 8000
```

API docs: http://127.0.0.1:8000/docs

Provenance is stored in SQLite. `ASCA_DATABASE_URL` selects the database; the default is
`sqlite+pysqlite:///./.asca/asca.db` (the `.asca/` directory is created with mode `0700` and is
ignored by Git). Only `sqlite+pysqlite:///` URLs are supported, for example
`ASCA_DATABASE_URL=sqlite+pysqlite:///:memory:` for a throwaway run. The schema is migrated on
startup. Keep the API on `127.0.0.1`: it has no authentication.

To preview the Python symbol index of a directory without writing anything, run
`uv run python -m asca.infrastructure.indexing PATH`. It prints one JSON line with
workspace-relative paths, qualified names, spans and fingerprints, never source text, and
never imports or executes the indexed code.

## Start the UI

In a **second terminal**:

```bash
cd apps/web
npm run dev
```

Open http://127.0.0.1:5173. The UI can show the API connection state, list capabilities,
display a synthetic provenance trace, and preview requests without submitting them to an agent.

## Verify this increment

```bash
uv run python scripts/run_checks.py
```

This creates `diagnostics/phase0-diagnostics.zip` containing command logs, JSON results,
versions, and summary. **Please share this ZIP before the next implementation phase.**
The check script never prints secret environment variables and does not contact CERN services.

If dependencies are not installed yet, run `bash scripts/bootstrap.sh` before the full check.
Failed or skipped checks must not be interpreted as successful checks.

## Search knowledge sources (M3)

The knowledge CLI searches INSPIRE-HEP, arXiv, HEPData, an optional local library and
configured MCP servers, and reports every source it could not consult. Nothing is sent
over the network without `--live`.

```bash
uv run python -m asca.infrastructure.knowledge providers
uv run python -m asca.infrastructure.knowledge search \
    "energy reconstruction liquid argon calorimeter neural network" --live
uv run python -m asca.infrastructure.knowledge fetch inspire 1920956 --live --format text
```

Configuration is optional and lives in `~/.config/asca/knowledge.toml` (mode 0600), or
the path given by `--config` or `ASCA_KNOWLEDGE_CONFIG`; it is never read from the
working directory. Tokens come only from `ASCA_` environment variables. See
[ADR 0040](docs/adr/0040-federated-knowledge-layer.md) and the
[M3 acceptance document](docs/development/m3-acceptance.md).

## Documentation

- [Roadmap v2](docs/roadmap.md) and [ADR 0037](docs/adr/0037-prioritize-evidence-to-code-vertical-slice.md)
- [Architecture](docs/architecture/overview.md)
- [Security](docs/security/security-model.md)
- [Testing](docs/development/testing.md)
- [UI design principles](docs/design/interface-guidelines.md)
- [Decision records](docs/adr/)

## Project state

| Capability | Phase 0 state |
|---|---|
| FastAPI and OpenAPI | Implemented |
| React workspace shell | Implemented |
| Synthetic provenance viewer | Demonstration only |
| CERN SSO | Not implemented |
| chATLAS MCP | Not implemented |
| Code generation | Not implemented |
| Sandboxed execution | Not implemented |

## Intellectual property and security

Start with a private repository. Do not commit CERN passwords, API credentials,
SSO tokens, or internal collaboration documents. A license will be selected deliberately
before public distribution. This project has no direct affiliation with CERN or ATLAS.


## Phase 1A.1 — Offline identity foundation

Authorization Code + PKCE S256 contracts, browser-bound transaction correlation and an isolated memory store are provided for tests only. CERN SSO authentication, browser callbacks, token exchange, JWT verification, and real sessions are **not implemented**. The public `/api/v1/identity/status` endpoint reports this accurately.

See [ADR 0004](docs/adr/0004-oidc-authentication-boundaries.md), the [OIDC security boundary](docs/security/oidc-identity-foundation.md) and the [Phase 1A.1 acceptance checklist](docs/development/phase1a1-acceptance.md).
