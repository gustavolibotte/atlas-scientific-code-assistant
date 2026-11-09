# Testing and evidence protocol

**No increment is accepted without a diagnostic bundle reviewed against its exit statuses.**

## Commands

```bash
bash scripts/bootstrap.sh
uv run python scripts/run_checks.py
```

`run_checks.py` executes Python compile checks, pytest with branch coverage, Ruff lint and
format checks, mypy strict typing, and frontend typecheck/build/test. It produces a JSON
summary and zipped logs under `diagnostics/` even if some checks fail.

The script uses only local test fixtures. CERN authentication, chATLAS, and external APIs
are not contacted. Frontend checks are **skipped with explicit status** if `node_modules` is
missing; skipped checks do not count as passing.

## Review gate

1. User runs checks on their macOS machine.
2. User uploads `diagnostics/phase0-diagnostics.zip`.
3. Review all check results, environment versions, and failure logs.
4. Investigate any failure or skipped mandatory test before proceeding.
5. Archive accepted diagnostic summaries with the corresponding Git commit.

Avoid logging access tokens or private material. Do not include `.env`, `.venv`, or
`node_modules` in diagnostic ZIPs.
