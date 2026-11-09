# Phase 0 acceptance checklist

All mandatory checks must pass before Phase 1 is implemented.

## Foundation

- [ ] Fresh checkout and `bash scripts/bootstrap.sh` succeed on macOS.
- [ ] `uv.lock` and `apps/web/package-lock.json` are generated and committed.
- [ ] API starts and `/api/v1/health/ready` returns a version.
- [ ] UI starts, navigation works, and status accurately reflects API connectivity.
- [ ] Synthetic trace is prominently labeled as synthetic.
- [ ] No CERN SSO or chATLAS integration is presented as operational.

## Quality and safety

- [ ] Python compilation, unit/property, API contract, security and architecture tests pass.
- [ ] Ruff lint and format checks pass.
- [ ] mypy strict checks pass.
- [ ] Frontend typecheck, unit tests and production build pass.
- [ ] No `.env`, credentials, external datasets or old RAG files in the repository.
- [ ] `diagnostics/phase0-diagnostics.zip` created and reviewed.

Passing the checklist proves Phase 0 software behavior only; it does not validate generated
scientific code or any CERN service because these features are not yet implemented.
