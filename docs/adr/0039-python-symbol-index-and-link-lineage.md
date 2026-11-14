# ADR 0039: Python symbol index and link lineage

- **Status:** Proposed (2026-11-13); accepted when the M2 pull request merges
- **Date:** 2026-11-13
- **Milestone:** M2 (Code symbol index and link staleness), `docs/roadmap.md` v2
- **Related:** [ADR 0037](0037-prioritize-evidence-to-code-vertical-slice.md),
  [ADR 0038](0038-persisted-provenance-graph-and-export-contracts.md)

## Context

M1 stores workspace revisions, code symbols and implementation links, but nothing
produces symbols: fingerprints are supplied by hand, and `link_freshness` compares a
link's symbol with the same key in the latest indexed revision only. M2 must extract
Python symbols with `ast` (qualified name, span, and a fingerprint of the normalized
AST that ignores formatting and comments), re-index on each workspace revision, and mark
links `stale` when the fingerprint changes and `orphaned` when the symbol disappears.
Exit: editing a function body marks its links stale; renaming without a body change is
detected as a move.

The change touches three things that need an ADR:

- a **trust boundary**: the application now reads files from a workspace it does not
  control;
- a **persisted contract**: new columns, and a fingerprint algorithm whose output must
  stay stable across Python versions and releases;
- **freshness semantics**: the meaning of `current`, `stale`, `moved`, `orphaned` and
  `unknown` changes from "same key in the latest revision" to a lineage walk.

## Decision

### 2.1 Fingerprint `python-ast/1`

`FingerprintAlgorithm.PYTHON_AST_1 = "python-ast/1"` names a custom, closed-world
canonical serializer in `asca.infrastructure.indexing.python_fingerprint`. The domain
only stores and compares opaque `(algorithm, sha256)` pairs.

**Grammar summary.**

- `digest(D) = sha256(b"asca:python-ast/1\n" + ENC(D))`. `ENC` emits typed, length-
  prefixed tokens: `~` for None, `[...]` for lists, `s<len>:<utf-8>` for strings,
  `i<hex>;` for ints, and `(Type field=value ...)` for nodes.
- Node fields come from a **pinned field table** (a literal dict of 104 node types,
  never derived from the running interpreter). An unknown node type, or a scalar of an
  unknown type, raises `UnsupportedSyntax`, which the extractor reports as a file issue.
- Constants are encoded with their exact type (`type(x) is ...`): `1`, `1.0`, `True`,
  `1j`, `b"1"` and `"1"` all differ; floats are encoded with `float.hex`, so `-0.0`
  and `0.0` differ and the encoder never meets the `int` digit limit. (Parsing pins
  that limit; see 2.4.)
- A field is omitted when it is None or `[]`. This makes 3.11 (no `type_params`), 3.12
  (`type_params=[]`) and 3.13 (`default_value=None`) produce identical output.
- **Merkle references.** A nested `FunctionDef`, `AsyncFunctionDef` or `ClassDef`
  is encoded as `(@def <name> <digest>)`. Each node is serialized once, with explicit
  stacks and no Python recursion.

**Normalizations.**

- A definition's digest never contains its own name; the parent emits it.
- A `Name` equal to the enclosing module-level definition's name (TOP) is encoded as
  `@top`, so renaming a recursive function, or a class whose methods mention it
  (`super(C, self)`, `C.CONST`, `-> C`), is still a move. Attribute names, argument
  names and string annotations are not substituted.
- Docstrings and every other no-op string statement (`Expr(Constant(str))`) are
  dropped at every depth.
- f-strings are flattened: nested `JoinedStr` merged, empty parts dropped, adjacent
  strings merged, and an empty format spec removed, so `f"{x:}"` equals `f"{x}"`.
- `ImportFrom.level=None` is read as 0.
- `del` targets are flattened: a `Tuple` or `List` target is replaced by its elements,
  recursively, so `del (a, b)`, `del [a, b]` and `del a, b` are equal. Formatters
  (`ruff format`, black) wrap a long `del` in parentheses, and deletion runs left to
  right in every spelling. Order and every other target still count.

**Coverage.** A function or method covers its decorators, full signature (defaults,
annotations, return annotation, PEP 695 type parameters), async-ness and body,
including nested definitions. A class covers decorators, bases, keywords, type
parameters and its whole body, so editing a method makes links to the class stale. The
module symbol covers the whole file without no-op strings. Duplicate qualified names in
one file are merged with `sha256(b"asca:python-ast/1:merged\n" + digests in source order)`.

**Versioning policy.**

- Any change of output for an input that already had a fingerprint needs a new id
  (`python-ast/2`), a new enum member, a migration that widens the CHECK constraint, and
  new goldens.
- Fingerprints with different algorithm ids are never compared; the result is
  `unknown` with reason `algorithm_changed`.
- **Monotone extension:** supporting syntax that used to yield `syntax_error` or
  `unsupported_syntax` (for example 3.14 template strings) keeps the id, provided every
  golden is unchanged.
- The field-table coverage test fails loudly when the supported Python range widens.
- Golden values live in `tests/contract/fingerprint_golden/python_ast_1/` as `.pysrc`
  files (CI runs `compileall` on `tests/`, so the corpora cannot be `.py`), plus
  normalization vectors in `expected.json` that pair a `del` statement with its
  formatter output. They are checked on Python 3.11, 3.12 and 3.13.

### 2.2 Symbol model

- `SymbolKind` is unchanged. The extractor produces module, class, function and method
  symbols. The module symbol has the qualified name `__module__` and spans the file.
- Classes nest (`Fit.Inner.m`); definitions inside function bodies are not symbols and
  stay part of the enclosing function's fingerprint. Lambdas, comprehensions,
  assignments and `type` aliases are not symbols.
- Duplicates (redefinitions, `if`/`else` and `try` variants, `@overload` stubs,
  property getter and setter) merge into one symbol: the last kind, the union span and
  the merged fingerprint.
- Names that are not ASCII identifiers, a top-level definition named `__module__`, and
  qualified names over 300 characters are skipped and counted, never stored.
- `CodeSymbol` gains `fingerprint_algorithm` (None for M1 hand-made fingerprints).
  `WorkspaceRevision` gains `file_issues` (sorted, unique paths, at most 10,000) and
  `source_digest`; an unindexed revision has neither. A symbol never lies in a file its
  own revision lists as an issue (`G.symbol.issue_file`).

### 2.3 Lineage freshness semantics

`asca.domain.provenance.lineage` replaces the latest-only comparison. `SymbolLineage`
precomputes, per indexed revision, the effective symbol map, the new symbols and the
disappeared symbols, grouped by `(language, algorithm, fingerprint)`. `trace(symbol_id)`
walks every later revision in sequence order from the linked symbol (the *origin*):

- **Same key present:** follow it.
- **Carried files:** when a file is listed as an issue in a revision (syntax error, too
  large, symlink, unreadable, ...), its last known symbols are carried forward. A link
  in such a file becomes `unknown` (`file_not_parsed`), never `orphaned`. This also
  holds when the link's symbol was never carried, because it was recorded in an
  unindexed revision: a revision that did not parse the file decides nothing about it.
  Carried symbols are never counted as disappeared.
- **Move rule:** when the key disappears, the link moves only when exactly one
  *plausible* new symbol has an equal fingerprint and no other disappeared symbol shares
  that fingerprint. Plausible means the same file, or the same final name segment in
  another file. A rename and a file move in one revision is therefore not a move.
  "New" and "disappeared" are measured from the last indexed revision in which the
  traced symbol was actually parsed. While its file was carried, other files kept
  changing: a function cut from a file that was left broken and pasted into another
  file is a move once the first file parses again, exactly as if the broken revisions
  had never been indexed, and a same-fingerprint symbol that disappeared during that
  window is still a rival.
- **Unindexed revisions** never decide anything; their same-key symbols are recorded
  only for attachment.

Reasons and freshness (`FreshnessReason` → `LinkFreshness`):

| Reason | Freshness |
|---|---|
| `unchanged` | `current` |
| `relocated` | `moved` |
| `content_changed`, `relocated_and_changed` | `stale` |
| `removed`, `ambiguous_relocation` (with up to 10 candidates) | `orphaned` |
| `not_fingerprinted`, `not_indexed`, `file_not_parsed`, `algorithm_changed` | `unknown` |

`SymbolTrace` carries the origin, the last seen symbol, the current symbol (when it is in
the latest indexed revision and the link is not orphaned), the revision where the link
was lost, the candidates and the successor ids. Its `__post_init__` enforces the
consistency rules `R.trace.*`. `evaluated_revision` is None for `not_indexed`, and also
for `not_fingerprinted` when nothing has been indexed since the origin.

**Attachment by lineage.** The inspector attaches an implementation link, and a
symbol-level verification link, to symbol S when the link's symbol is S or one of them
is a successor of the other. A renamed function therefore lists its decisions as
`moved`, and an unrelated symbol that reuses an old name does not inherit them. A lost
link stays orphaned even if its key reappears later. `LinkFreshness` values, exports and
the export schemas are unchanged; exports compute `freshness` with one `SymbolLineage`
per export.

**Read model and API (additive only).**

- `DecisionView.trace`, `FunctionInspection.file_issue`, and a new
  `link_health(graph)` that lists every implementation link with its trace, ordered
  orphaned, stale, moved, unknown, current, then by decision and link creation.
- `RevisionDTO` gains `source_digest` and `file_issue_count`; `CodeSymbolDTO` gains
  `fingerprint_algorithm`; `ImplementationDTO` gains the reason, the linked, current
  and last-seen locations, the loss revision, candidates, and the file issue for
  `file_not_parsed`; `SymbolListResponse` gains the listed revision's `file_issues` and
  the `links` health list; `FunctionInspectionResponse` gains `file_issue`.
- The symbol list now includes decision titles. Local single-user mode returns every
  access class; viewer filtering is still M10, and the route carries the same comment as
  the inspection route.
- No new route and no frontend change.

### 2.4 Workspace trust boundary

Indexed code is untrusted data. It is never executed, imported or compiled.

**Application ports.** `WorkspaceReader.read(suffixes, limits) -> WorkspaceSnapshot`
and `SymbolExtractor.extract(data, limits) -> FileExtraction`. The extractor never sees
paths; identity comes from the path, which is the service's concern. `IndexLimits`
defaults: 5,000 files, 512 KiB per file, 32 MiB in total, directory depth 32, 100,000
directory entries, 500,000 AST nodes and 5,000 symbols per file, 20,000 symbols per
revision.

**Reader rules** (`FilesystemWorkspaceReader`, POSIX only):

- fd-relative traversal with `O_NOFOLLOW`; symlinks are never followed. A symlinked
  source file is reported as `symlink`, and a symlinked directory is skipped.
- Files are opened non-blocking and checked with `fstat`: a FIFO, socket or device
  named `*.py` is `not_regular` and never read (opening a socket fails with `ENXIO` on
  Linux and `EOPNOTSUPP` on macOS; both mean `not_regular`); an entry the listing already reports as
  a socket or device is not even opened, and a symlink candidate still counts toward the
  file limit. A file larger than the limit, or one
  that grows during the read, is `too_large`; at most `max_file_bytes + 1` bytes are read.
- Names that are not strict UTF-8, not printable, contain `\` or `:`, or make a path
  over 500 characters are counted and never echoed. Hidden entries, `__pycache__`,
  `node_modules`, `site-packages`, `*.egg-info`, virtual environments, and root-level
  `build`, `dist` and `venv` are skipped. Other file systems are skipped by default.
- **Fail closed:** exceeding the file, total-byte, depth or entry limits, or an
  unreadable directory (or a root that cannot be opened or listed), raises
  `WorkspaceIndexError` with a fixed message that contains no path. Nothing is recorded, so a hidden subtree never looks deleted.

**Extractor rules** (`PythonAstExtractor`):

- A NUL byte is `binary`.
- **Codec allowlist:** a PEP 263 cookie is parsed by our own decoder and must name
  UTF-8, Latin-1 or ASCII; anything else is `unsupported_encoding`. No codec lookup
  ever runs on an attacker-chosen name.
- `ast.parse` runs with warnings suppressed. Syntax errors are `syntax_error`;
  recursion or memory errors and node or symbol limits are `too_complex`; an unknown
  node type is `unsupported_syntax` for the whole file. Exception messages are never
  kept, because they echo source text.
- **The outcome never depends on the calling process.** `ast.parse` runs in a fresh
  thread (on Python 3.11 the parser's recursion budget shrinks with every frame already
  on the caller's stack), one parse at a time, with CPython's default decimal `int`
  digit limit (4,300) pinned and the recursion limit raised to at least its default
  (1,000) for the parse. A decimal literal longer than 4,300 digits is therefore
  `syntax_error` whatever `PYTHONINTMAXSTRDIGITS` or `-X int_max_str_digits` says.
- An AST deeper than 1,000 nodes (the module is depth 1) is `too_complex`. Every
  supported interpreter parses trees up to that depth, so a deep file gets the same
  issue on 3.11, 3.12 and 3.13 instead of only on the interpreter whose parser gives up
  first. The deepest file in the standard library and the installed dependencies is
  under 100. The bound is part of `python-ast/1`.
- `extract` is total: it never raises for any input bytes.

**Indexing service.** `build_index` validates the extractor set and the snapshot again
(defence in depth), refuses an empty workspace unless `allow_empty` is set (so a
misconfigured root cannot orphan every link), enforces the symbol budget, and computes a
`source_digest` over the algorithm ids, paths, content hashes and issues.

Architecture tests keep `asca.infrastructure.indexing` stdlib-only plus domain and
application, forbid modules such as `importlib`, `subprocess`, `pickle` and `socket`,
forbid calls to `exec`, `eval`, `compile` and `__import__`, and keep `ast`, `os` and
`pathlib` out of the domain and application layers.

### 2.5 Trigger

- `IndexingService.index_workspace` is the only writer. It records one revision per
  call in a single batch (no skip-if-unchanged, no compare-and-set retry). M5's
  workspace manager will call it after each mediated change with the commit sha, and
  will create implementation links from symbol ids of the returned revision, never
  from model claims. Indexing should then run in a worker process.
- `python -m asca.infrastructure.indexing ROOT` is a read-only preview CLI. It prints
  fingerprints, issues and the digest as JSON, never source text or absolute paths,
  and never touches a database.
- **No HTTP route.** A POST that makes the unauthenticated loopback API read a
  server-side path would change the trust boundary (cross-site form POST, DNS
  rebinding) and break the frozen route allowlist. A future route needs its own ADR.

### 2.6 Persistence

- Migration `0002` is purely additive (`ADD COLUMN` only):
  - `code_symbols.fingerprint_algorithm`, with CHECKs for the known ids and for "an
    algorithm needs a fingerprint";
  - `workspace_revisions.source_digest`, with a CHECK that only an indexed revision has
    one;
  - `workspace_revisions.file_issues` as JSON, default `'[]'`.
- No new table and no new trigger: 17 tables and 34 triggers, and the append-only
  triggers cover the new columns. Downgrade drops the columns (SQLite 3.35 or later).
- Loading validates the `file_issues` JSON strictly; any deviation is a
  `StoredGraphIntegrityError`.
- **No export-contract change.** `src/asca/contracts/exports/v1/*.json` and
  `released.json` are untouched and no golden is regenerated. `implemented_by` keeps
  describing the asserted link (origin symbol and fingerprint) plus `freshness`, now
  computed by lineage. The algorithm id, the reason and the current location are
  served by the inspector only.

## Consequences

- Editing a function body makes its links `stale` (`content_changed`); renaming it
  without a body change makes them `moved` (`relocated`) and shows the new location;
  deleting it makes them `orphaned` with the revision where they were lost. Files that
  cannot be parsed make their links `unknown`, never `orphaned`.
  `tests/contract/test_symbol_index_end_to_end.py` proves this on a real directory and
  a SQLite file; `docs/development/m2-acceptance.md` maps every exit criterion and every
  trust-boundary rule to its tests.
- Three M1 test expectations change intentionally, because links now attach by lineage
  instead of by key:
  1. `tests/unit/test_provenance_inspection.py::test_list_symbols_worst_freshness_and_decision_count`:
     `calibrate` in `src/reco/calibration.py` lists `(1, moved)` instead of `(0, None)`.
  2. `tests/unit/test_provenance_inspection.py::test_symbol_without_links_warns_no_linked_decision`
     uses a new unlinked symbol in a third revision, because the moved `calibrate` now
     carries its link (`test_moved_symbol_shows_the_carried_link` covers that).
  3. `tests/contract/test_provenance_api.py::test_complete_project_symbols_listing`:
     `calibrate` lists `(1, "moved")`.
- API responses grow additively. Key-set contract tests were extended; no field was
  removed or renamed, and the export goldens are byte-identical.
- Every inspection, symbol list and export builds one `SymbolLineage`, which holds
  O(revisions × symbols) entries.

## Alternatives rejected

- **Hashing `ast.dump`.** Its output changes between Python versions (new fields,
  different defaults, different `repr`), so fingerprints would not be stable across
  3.11–3.13, and it cannot exclude a definition's own name or docstrings.
- **`tokenize.detect_encoding`.** The judge verified on 3.11.18, 3.12.3 and 3.13.18 that
  it calls the registered codec search functions with the attacker-chosen cookie name
  before any allowlist can apply.
- **Placeholders for every qualified-name segment.** A bare `fit` inside method
  `C.fit` refers to a module global, never to the method; substituting it hides real
  references and can orphan a renamed method. Only the module-level TOP name is
  substituted.
- **Truncated or partial indexes.** They add states (`truncated`, pending,
  `INDEX_INCOMPLETE`) and risk false orphans. Failing closed on limits is simpler.
- **Latest-only comparison** (M1). It cannot detect moves, turns every parse failure
  into `orphaned`, and lets an unrelated symbol that reuses a name inherit old links.
- **A child table for file issues.** A JSON column on the revision is enough for M2,
  keeps the table and trigger counts unchanged, and is validated strictly on load.
- **An HTTP trigger.** See 2.5.

## Risks

1. **Graph growth.** Every revision stores a full symbol set and every load validates
   the whole graph; each lineage holds O(R·S) entries. Acceptable at M2 and M5 scale;
   delta or as-of loads come later.
2. **Conservative staleness.** Class and module fingerprints are deep, and decorators
   and annotations are hashed. A docstring-only edit stays `current`.
3. **Move limits.** A rename and an edit in one revision gives `orphaned`. A rename plus
   a file move in one revision gives `orphaned`. Moving into a class while adding `self`
   gives `orphaned`. A lost link stays orphaned even if the key reappears. A lone stub
   deleted and an unrelated identical stub added in the same file can be a false
   `moved`; it is a warning state and shows its target.
4. **`@top` substitution is a heuristic.** Local shadowing of the top-level name can
   produce `orphaned` or, in contrived cases, a false `moved`. A method that calls
   itself through `self.m()` is orphaned when renamed.
5. **Interpreter syntax range.** 3.12+ syntax on a 3.11 indexer gives `syntax_error`, so
   the link is `unknown`, never `orphaned`. Python 3.14 needs a table extension, and the
   coverage test fails loudly.
6. **In-process parsing.** The warnings filter, the `int` digit limit and the
   recursion limit are process-global. Parses are serialized by a lock, but another
   thread of the same process sees the pinned values while a parse runs. Catching
   `MemoryError` is coarse; worst-case transient memory is about 330 MB for 512 KiB of
   pathological input. Inputs that exhaust the parser's own fixed stack (brackets
   nested about 200 deep around deep expressions, at AST depths of about 300 to 400)
   are `too_complex` everywhere, but the exact boundary can differ by a level between
   interpreter versions. M5/M6 should run the indexer in a worker process.
7. **Reader coverage.** POSIX only. `.gitignore` is ignored. Hard links are read.
   Symlinked package directories are not indexed. A directory replaced by a symlink
   makes its links `orphaned`, not `unknown`.
8. **Non-ASCII identifiers** are skipped, because the domain regex is ASCII. This also
   blocks confusables.
9. **CHECK widening.** A new algorithm id, or a new language in M9, needs an SQLite
   table rebuild that recreates the append-only triggers.
10. **Intentional behaviour change.** Links attach by lineage, so the three M1 test
    expectations listed under Consequences change.

## Open questions for the maintainer (defaults already applied)

| # | Question | Default in M2 |
|---|---|---|
| a | Exclude docstrings from fingerprints? | Yes. |
| b | Add the algorithm id and current location to v1 `implemented_by` before the M1 merge? | No; served by the inspector only. |
| c | Ship the read-only preview CLI? | Yes; it is the first thing to cut. |
| d | Are the default limits (5,000 files, 512 KiB per file, 32 MiB total, depth 32, 100k entries, 500k nodes, 5k symbols per file, 20k per revision) acceptable? | Applied as the `IndexLimits` defaults; to be confirmed. Every limit fails closed and writes nothing. |
| e | Allow Unicode identifiers later, with confusable checks? | Not in M2: non-ASCII identifiers are skipped and counted, because the domain name rule is ASCII. |
