# ADR 0037: Prioritize the evidence-to-code vertical slice; freeze CERN web authorization work

- **Status:** Accepted (2026-11-12)
- **Date:** 2026-11-12
- **Supersedes:** The ordering of `docs/roadmap.md` v1 (Phase 1 before Phases 2–5)
- **Does not supersede:** ADRs 0004–0036 remain valid for the identity code they describe

## Context

The project plan states that the most important near-term goal is to demonstrate
one complete cycle: *request → evidence retrieval → explicit scientific decisions →
generated code → executed tests → auditable provenance*. The plan explicitly warns
against "an indefinite sequence of documentary prototypes".

Repository state at `cc1ba73` (2026-11-12):

| Area | State |
|---|---|
| Foundation (FastAPI, React shell, CI, architecture tests) | Implemented |
| CERN OIDC native client, JWKS/JWS, claims, role observation | Implemented and heavily tested |
| CERN web BFF authorization (G1–G10) | All gates `blocked` on operator/provider evidence |
| Persisted evidence and provenance model | Synthetic in-memory demo only |
| Knowledge providers (chATLAS, INSPIRE, GitLab, local) | Port only, no adapter |
| LLM planner, code generation, workspace, execution | Not started |

Thirty-five of the thirty-seven merged pull requests addressed identity. The
remaining web-authorization gates cannot be closed from inside the repository: they
need CERN operator and resource-owner evidence that the maintainer cannot obtain.

Two further facts lower the urgency of web authorization:

1. The first deployment target is a **single-user local application** bound to
   `127.0.0.1` on the maintainer's Mac. Logging into ASCA itself adds no security
   there beyond operating-system account isolation.
2. Access to chATLAS and CERN GitLab is a **per-resource authorization** problem. An
   ASCA ID Token is not an access token for those services (ADR 0004). Remote MCP
   servers carry their own OAuth authorization flow, which a generic MCP client
   adapter has to support regardless of ASCA login.

## Decision

1. Freeze the CERN web authorization track at Phase 1A.2.5C9. Keep its code, tests,
   contracts and ADRs green and unchanged. Do not add further C-series increments.
2. Reorder the roadmap (`docs/roadmap.md` v2) into vertical milestones M1–M10. Each
   milestone must deliver running behaviour that moves the evidence-to-code cycle
   forward and has objective exit criteria.
3. Resume web authorization only when one of these holds:
   - the hosted multi-user deployment milestone (M10) starts; or
   - a concrete connector requires an ASCA-managed CERN token and the MCP client's
     own authorization flow is insufficient.
4. Lighten process overhead without lowering quality:
   - one acceptance document per **milestone**, not per pull request; per-PR
     acceptance criteria live in the PR description;
   - ADRs only for decisions that change architecture, trust boundaries or
     public contracts;
   - CI remains the single source of truth; the local diagnostics ZIP becomes
     optional.
5. Keep every existing invariant: strict typing, architecture-direction tests,
   negative security tests, no secrets in fixtures or logs, external content treated
   as data, and no claim of ATLAS endorsement without evidence.

## Consequences

- The first end-to-end demonstration (Experiment B, linear amplitude estimators)
  becomes reachable within the next milestones instead of after the identity track.
- The application runs without login in local mode. The API must keep listening only on
  loopback; binding to other interfaces is unsupported until an authentication layer
  exists.
- Some identity modules stay unused by runtime code for a while. They remain covered
  by tests and are not removed.
- If chATLAS MCP proves to require ASCA-managed tokens, the existing native OIDC
  client is the starting point, and this ADR's resumption trigger applies.
