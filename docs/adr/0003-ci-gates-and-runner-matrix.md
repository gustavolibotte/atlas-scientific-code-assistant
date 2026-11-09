# ADR 0003: Stable CI gates and explicit runner images

- **Status:** Accepted
- **Date:** 2026-11-09
- **Scope:** GitHub Actions and branch governance

## Context

The initial workflows passed on macOS and Ubuntu, but they used actions with deprecated Node.js 20 runtimes. The `ubuntu-latest` image was also transitioning to Ubuntu 26.04. Protecting `main` by selecting every matrix check would require changing branch rules whenever the matrix changes.

## Decision

1. Require a pull request for changes to `main` and configure zero required human approvals while the project has one maintainer.
2. Run backend tests on Ubuntu 24.04, Ubuntu 26.04, and macOS, with Python 3.11–3.13.
3. Run frontend checks on Ubuntu 24.04 and Ubuntu 26.04 with Node.js 22.
4. Upgrade `checkout` to v7, `setup-node` to v7, and `setup-uv` to v10.
5. Limit `GITHUB_TOKEN` permissions to read-only repository contents; do not persist checkout credentials.
6. Add stable `Backend quality gate` and `Frontend quality gate` aggregation jobs. Each must fail if any job in its matrix fails.
7. Enforce locked dependency installations and a minimum of 85% combined backend branch-and-statement coverage in CI.
8. Use bounded job timeouts and cancel superseded workflow executions.

## Consequences

- The ruleset can require two stable checks regardless of later matrix changes.
- The job count increases; private-repository Actions usage must be monitored.
- New runner images may expose previously hidden compatibility problems.
- Third-party actions are currently referenced by maintained major tags; pinning to audited immutable commit SHAs is a subsequent supply-chain hardening task.
- `StarletteDeprecationWarning` and transitive npm deprecation notices remain tracked compatibility issues, not suppressed test failures.

## Validation

- Local: `uv run python scripts/run_checks.py`
- Policy regression: `uv run pytest -q tests/ci/test_workflow_policy.py`
- Remote: both aggregate gates must pass on a pull request before merge.
