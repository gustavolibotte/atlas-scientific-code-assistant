# Contributing

All source code, comments, tests, commit messages, and technical documentation are in English.

## Quality gate

Every contribution must include relevant tests, update the documentation when behavior
changes, and pass `uv run python scripts/run_checks.py`. Fix all failures before merging.

Use small branches and Conventional Commits. Domain modules must never import from FastAPI,
HTTP clients, databases, or any external knowledge provider.

For security or authentication changes, supply explicit negative tests. Never embed live
CERN credentials in fixtures, examples, or logs.

See [testing](docs/development/testing.md) and [architecture](docs/architecture/overview.md).
