# ADR 0040: Federated knowledge layer (public sources first)

- **Status:** Accepted
- **Date:** 2026-11-14
- **Milestone:** M3 (Federated knowledge layer), `docs/roadmap.md` v2
- **Related:** [ADR 0002](0002-evidence-boundaries.md),
  [ADR 0037](0037-prioritize-evidence-to-code-vertical-slice.md),
  [ADR 0038](0038-persisted-provenance-graph-and-export-contracts.md),
  [ADR 0039](0039-python-symbol-index-and-link-lineage.md)

ASCA is not an official ATLAS or CERN product. Nothing in this ADR claims ATLAS
endorsement, and authority categories remain ASCA project policy (ADR 0038, section 5).

## Context

M1 can store sources, versions and claims, but nothing finds them. M3 must answer one
query from several knowledge sources (INSPIRE-HEP, arXiv, HEPData, a local curated
library, and MCP servers such as chATLAS or `cerngitlab-mcp`), report every source that
could not be consulted, and de-duplicate results by persistent identifier. Exit: one
query returns normalized evidence from at least two providers, and an unavailable
provider is reported, not hidden.

This opens four trust boundaries that did not exist before:

1. **Outbound network access** to public services, from the user's machine and IP.
2. **Untrusted response content.** Titles, abstracts and tool output are written by
   third parties and may contain terminal escape sequences, bidi overrides, prompt
   injection text, XML entity bombs or oversized bodies.
3. **User-configured MCP servers**, reached over the network (with a bearer token) or
   launched as local processes (stdio).
4. **Configuration as a code-execution input.** A configuration file can name a
   command to launch, so whoever controls the file controls what runs.

## Decision

### 1. Async port, models, errors as values

`KnowledgeProvider` (in `asca.application.ports`) is an async protocol with
`descriptor`, `search(query)`, `fetch(ref)` and `health(deep=...)`. The models live in
`asca.application.knowledge.models`: frozen, slotted dataclasses validated in
`__post_init__`, with fixed error messages that never echo provider text.

- Expected failures are returned as `ProviderError(kind, code)` values from a closed
  vocabulary and are never raised. An exception escaping an adapter is a bug; the
  federation maps it to `INTERNAL_ERROR/unexpected_exception` without logging its text.
- Every adapter applies `asyncio.timeout(descriptor.timeout_s)` itself.
- `fetch` takes a `CandidateRef(provider_id, native_id)`, never a URL. Each adapter
  builds its request from a fixed template and a native id checked by its own regex.
  Nothing in a response ever causes another request.
- `KnowledgeQuery.access_class` states how sensitive the query text is; see section 5.
- Partial dates are kept partial (`PartialDate`); ASCA never invents a day.
- Fetched text is a plain-text rendering hashed with M1 `sha256_text`: abstracts as
  `asca-abstract-text/1` (`title\n\nabstract\n`), local files verbatim, MCP text as
  returned (after secret-echo redaction). JSON is never the canonical text, because
  JSON escaping would break the verbatim quote matching M4 relies on.

### 2. Authority suggestion policy `asca-authority/1`

`suggest_authority(candidate)` is a pure, versioned function. It suggests only
**A** (published), **D** (working material) or **E** (automated inference), per
candidate and never per group. B and C are never suggested.

- INSPIRE suggests A only for a record marked `refereed: true` that lists a curated,
  non-HEPData DOI and is public. Everything else from INSPIRE is D.
- **arXiv is D.** A preprint is not the version of record, and the DOI in arXiv
  metadata is supplied by the authors. The refereed version reaches A through its
  INSPIRE member, which sits in the same evidence group.
- HEPData records are D (datasets; their categories are an ADR 0038 decision).
- The local library honours the curator's hint, but a `published` hint without public
  access and a published-scheme identity PID is downgraded to D.
- MCP results are D or E (the configured ceiling); model-generated answers are always E.

Registration (`plan_registration`, `KnowledgeRegistrationService`) needs an explicit
human choice. Choosing above the suggestion, or choosing B, requires a written basis.
Nothing is ever promoted automatically. The suggestion, the rule, the choice, the
provider, the adapter version, the native id and the retrieval time are written into
the M1 `authority_basis`; the access source goes into `access_conditions`. A source and
its first version are written in one commit (`ProvenanceService.record_source_version`).

### 3. Federation

`FederationService` runs the selected providers concurrently (at most 8 at a time).

- Each provider gets an outer deadline of its own timeout plus a 3 s grace, so the
  worst-case wall clock is the largest timeout plus 3 s (at most 33 s).
- **Every configured provider is reported**, enabled or disabled, with status `ok`,
  `partial` (items dropped), `failed` or `skipped`, and a `ProviderError` when not OK.
  The CLI ends its text output with "Sources not consulted: ...".
- Results are contract-checked (provider id, kind, count, ranks, access class);
  a violation fails that provider with `contract_violation`.
- Candidates are grouped with a union-find over **identity PIDs only** (DOI, arXiv id,
  INSPIRE record, identity CDS report numbers). Related PIDs never merge. A component
  holding two records of one provider, two INSPIRE records or two arXiv ids is **split**
  into flagged singletons (`ambiguous_identity`); nothing is merged on an uncertain
  edge. `multiple_dois` and `access_mixed` are informational flags.
- Fields are never fused: each member keeps its own title, version, access class,
  licences and suggestion. The group's effective access class is the most restrictive
  member's (ADR 0038, section 6).
- Group order is `(best rank, provider precedence, key)`. The result never depends on
  completion order or input order (property tested).
- **No cache.** Provenance needs the retrieval time and a hash of the actual retrieval.

Providers are built from validated settings by
`asca.infrastructure.knowledge.factory.build_federation`: enabled providers are
instantiated, disabled ones are passed as descriptors so they are still reported, and
the precedence is the configured order, then `inspire, arxiv, hepdata, local`, then MCP
servers in configuration order. Building a provider never touches the network or the
filesystem.

### 4. Outbound HTTP policy

- One runtime HTTP stack: **httpx2** (the stack the MCP 2.x SDK uses). `httpx` stays a
  dev-only dependency for the FastAPI test client.
- Base URLs are module constants; no setting can change them.
- TLS verification is always on; no setting can disable it. httpx2 uses `truststore`
  on macOS and Windows and honours `SSL_CERT_FILE`/`SSL_CERT_DIR`.
- Redirects are never followed (`redirect_refused`); `Accept-Encoding: identity` is
  forced and any other `Content-Encoding` is refused; every response is byte-capped
  before and while reading.
- A generic User-Agent (`asca-knowledge/<version>`) with no personal data, one
  connection for arXiv, minimum request intervals (INSPIRE 0.35 s, arXiv 3 s,
  HEPData 1 s), and **no retries**. The interval gate opens only once the monotonic
  clock has really reached the release time (an event loop may wake a sleeper early),
  and the client is built before the gate opens, so the measured spacing between
  requests never falls below the interval.
- Bot-challenge pages (`cf-mitigated: challenge`) are reported as
  `BLOCKED/bot_challenge`. They are never solved, retried or evaded.
- XML is parsed only through `defusedxml` with DTDs and entities forbidden; JSON is
  parsed strictly (no duplicate keys, no NaN, bounded depth).
- Proxies come from the environment (or explicit configuration) and are wired into
  the transport, because an explicit httpx2 transport ignores environment proxies.

### 5. Query egress by access class

Each descriptor declares `max_query_access`. Public providers (INSPIRE, arXiv,
HEPData) accept only public queries; the local library accepts any; MCP servers accept
what their configuration declares. The federation skips a provider with
`query_access_class` before calling it, and adapters refuse such queries as well
(defence in depth). An internal query therefore never leaves the machine towards a
public service.

### 6. MCP client

- The official `mcp` SDK 2.x, `mode="auto"`, **one session per operation**, with no
  sampling, elicitation or roots callbacks, and with server instructions and tool
  descriptions never stored or shown.
- Only the configured tools are called, and their input schemas must match the
  configured argument names and types. An optional SHA-256 pin of the tool definitions
  refuses a changed server before any call.
- Results are data. PIDs asserted by an MCP server are recorded as **related**, never
  identity, so internal tool output never merges into public evidence groups.
- Secrets that a server echoes back are redacted (`[REDACTED]`) and counted.
- stdio servers run behind a stdlib-only **guard process** that sets resource limits
  (CPU, open files, file size, address space on Linux) and caps output lines (4 MiB)
  and total output (16 MiB), because the SDK's stdio buffer is unbounded. The child
  gets only the SDK's default environment plus explicitly mapped `ASCA_` variables, and
  a fresh 0o700 working directory. **This is resource protection, not a sandbox**
  (isolation is M6).
- AGPL-licensed servers such as `cerngitlab-mcp` only ever run as separate processes;
  they are never imported.

### 7. Configuration and secrets

- The configuration path is `--config`, then `ASCA_KNOWLEDGE_CONFIG`, then
  `$XDG_CONFIG_HOME/asca/knowledge.toml` (default `~/.config/asca/knowledge.toml`).
  It is **never searched in the working directory**: opening an untrusted checkout
  must not launch processes. A relative `XDG_CONFIG_HOME` is ignored.
- The file is opened with `O_NOFOLLOW` and must be a regular file of at most 64 KiB,
  owned by the current user and not group- or world-writable. When it configures a
  stdio server, its directory must not be group- or world-writable either. A stdio
  command must be absolute, is resolved with `realpath`, and must be an executable
  regular file owned by the user or root and not group- or world-writable.
  Some interpreters fail this check by design: the python.org framework build on macOS
  is group-writable by `admin`, so pointing a stdio server straight at it gives
  `unsafe_command`. Use an interpreter you own (for example one installed by `uv`), or
  a user-owned wrapper script with mode 0755. The test suite runs its fake stdio server
  through such a wrapper for the same reason.
- Every table forbids unknown keys, so an inline `token` or `password` is refused.
  Errors print a fixed code plus the `loc` and `type` of each problem, never a value.
- Secrets come from the environment only, named by `ASCA_`-prefixed variables
  (`token_env`, stdio `env` sources), so a shared configuration cannot point a server
  at `GITHUB_TOKEN`. Tokens are never accepted on the command line and the CLI never
  prompts. Secrets are held in `RedactedSecret`, which refuses formatting and pickling.
- **Credential boundary for M4:** no type in `asca.application` has a field able to
  carry headers, tokens, cookies or credentialed URLs; an architecture test enforces
  this. The planner can therefore never see a credential.

### 8. No HTTP route in M3

The knowledge layer is reachable only through the CLI
(`python -m asca.infrastructure.knowledge`). The API is unauthenticated and bound to
loopback, but a cross-site simple GET needs no preflight and DNS rebinding can read the
response. An outbound-triggering route would let any web page spend provider rate limits
from the user's IP, or make MCP calls carrying the user's chATLAS token.
`/api/v1/system/capabilities` is unchanged (`chatlas` stays `NOT_IMPLEMENTED` until
ADR 0041 records scenario A).

A future route (M7, its own ADR) needs at least: POST with a JSON body and a custom
header (forcing a preflight), a Host allowlist (`127.0.0.1:<port>`, `localhost:<port>`,
`[::1]:<port>`), an Origin allowlist and a `Sec-Fetch-Site` check, a per-launch CSRF
token, per-provider rate limits, and results filtered by the viewer's access class.
Separately, the existing read routes lack a Host allowlist; a small hardening PR is
recommended before registered internal evidence is common.

### 9. Fixtures, licences and live tests

- CI runs offline. Tests replay recorded exchanges (`asca-http-fixture/1`) through
  the same bounded transport as production; an unknown request fails the test and never
  falls through to the network. A process-wide kill switch in `tests/conftest.py`
  refuses every non-loopback connection unless `ASCA_LIVE=1`, and `CI` together with
  `ASCA_LIVE` is refused.
- Live tests are marked `live`, opt-in with `ASCA_LIVE=1`, and never run in CI
  (asserted by `tests/ci/test_workflow_policy.py`).
- Recordings are made by `scripts/record_knowledge_fixtures.py --live` from a fixed
  scenario table (public providers only), with sanitizers and write checks. Only CC0
  metadata (ids, titles, DOIs, dates, at most three author names) is committed.
  Abstracts and full text are replaced with synthetic text; emails, ORCIDs and
  affiliations are never kept. Local and MCP fixtures are synthetic.

### 10. Dependencies and licences

Runtime additions: `mcp>=2.3,<3` (MIT), `httpx2>=2.16,<3` (BSD-3-Clause) and
`defusedxml>=0.7.1,<0.8` (PSF-2.0); dev: `types-defusedxml` (Apache-2.0). Transitive
additions are MIT, BSD-3-Clause, Apache-2.0 or PSF. Nothing AGPL is imported, and an
architecture test pins the set of third-party packages `src` may import.

## Exit evidence

`tests/contract/test_knowledge_federation_end_to_end.py` runs the exit query
"energy reconstruction liquid argon calorimeter neural network" through the real
factory over recorded fixtures plus a synthetic internal local note. INSPIRE (5 of 17)
and arXiv (4) answer, HEPData is reported as `BLOCKED/bot_challenge` (403), and the
local note is returned. The refereed INSPIRE record 1920956 (suggests A), its arXiv
preprint 2109.05124v2 (D) and the local note (D) form one `access_mixed` group keyed by
the journal DOI; INSPIRE 1969369 and arXiv 2111.08590v1 form a second cross-provider
group. Seven groups in total; the CLI JSON is byte-identical to the reviewed golden
`tests/contract/golden/knowledge_search_exit.json` and stable over 20 shuffled runs
with random per-host delays. The INSPIRE ranking drifted between the design check and
the recording (1920956 is now rank 1, the thesis 2744105 rank 3); the recording was
kept and the expected order updated, as the spec requires. The same file registers the
fetched INSPIRE and arXiv records on one Source with two versions and checks a quote
against the fetched text.

## Consequences

- **HEPData is provisional.** Its search response is currently a Cloudflare challenge
  from this environment (recorded as the exit test's failing provider). The parser's
  field names come from the hepdata-cli 0.3.1 source and must be confirmed against a
  recording made on the maintainer's Mac; record fetch returns `fetch_unsupported`
  until then.
- **DNS rebinding gap accepted.** MCP URLs are checked against non-global addresses
  before each session, but the address can change between the check and the connect
  (time-of-check to time-of-use). Only user-configured URLs are affected; provider URLs
  are constants. When a proxy is used, the proxy resolves names and the check is
  skipped.
- **stdio is not sandboxed.** The guard bounds resources and output but gives no
  filesystem or network isolation; that is M6.
- **The local library reads in a worker thread.** A read that hangs on a stuck
  filesystem returns `provider_timeout` on time, but the CLI process can only exit once
  the thread finishes.
- **A retrieval record and a fetched-text store are deferred to M4** (a
  `SourceRetrieval` record with provider, adapter version, ref, source URL, raw hash
  and licences; migration 0003; export schema v2; its own ADR). Until then the
  `authority_basis` sentence carries the retrieval facts.
- No CLI `register` in M3: choosing the project and store is planner and UI work. The
  library path M4 needs is complete and tested.

## Open questions for the maintainer (defaults applied)

| # | Question | Default |
|---|---|---|
| 1 | Should public ATLAS-CONF / ATL-PHYS-PUB notes be suggested above D? | No. INSPIRE_OTHER gives D; a human may choose B with a basis. |
| 2 | Should proceedings with a DOI but `refereed` absent be suggested A? | No (D). A human may choose A with a basis. |
| 3 | Should MCP-asserted PIDs merge with public records? | No. They are related only; revisit after ADR 0041. |
| 4 | Is the HEPData record fetch acceptable as deferred until maintainer-recorded fixtures exist? | Yes. Search only in M3. |
| 5 | Should the probe report hide the host by default? | Yes; `--show-host` opts in (M3b). |
| 6 | Is the access class for MCP servers required in configuration (no default)? | Required. |
| 7 | Should M4 add a `SourceRetrieval` record and a fetched-text store (export v2)? | Yes, with its own ADR. |
| 8 | Should the macOS keychain be a token source? | Deferred. Workaround: `export ASCA_CHATLAS_TOKEN="$(security find-generic-password -w -s asca-chatlas)"`. |
| 9 | Should a Host-allowlist hardening PR for existing read routes land before M4? | Recommended. |
| 10 | Should cerngitlab-mcp's licence and install path be confirmed for the stdio docs? | AGPL assumed; separate process only. |
