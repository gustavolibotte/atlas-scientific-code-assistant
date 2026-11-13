"""Symbol lineage across revisions and the freshness reasons of implementation links."""

import random
from dataclasses import dataclass, field, replace
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from provenance_builders import (
    CompleteProject,
    build_complete_real_project,
    fingerprint,
    make_service,
)

from asca.application.demo import DEMO_TIME
from asca.domain.provenance import (
    FRESHNESS_OF_REASON,
    MAX_CANDIDATES,
    CodeSymbol,
    FileIssue,
    FileIssueKind,
    FingerprintAlgorithm,
    FreshnessReason,
    IdKind,
    ImplementationLink,
    Language,
    LinkFreshness,
    Project,
    ProjectId,
    ProvenanceGraph,
    ProvenanceInvariantError,
    RecordNotFoundError,
    RevisionId,
    SymbolId,
    SymbolKind,
    SymbolLineage,
    SymbolTrace,
    WorkspaceRevision,
    link_freshness,
    make_id,
    trace_symbol,
)

pytestmark = pytest.mark.unit

A = "src/a.py"
B = "src/b.py"
ALGORITHM = FingerprintAlgorithm.PYTHON_AST_1
_AUTO = object()

# ---------------------------------------------------------------------- graph builder


@dataclass
class History:
    """Builds a graph of revisions and symbols directly, with ids from a seeded RNG."""

    seed: int = 0
    revisions: list[WorkspaceRevision] = field(default_factory=list)
    symbols: list[CodeSymbol] = field(default_factory=list)
    project: Project = field(init=False)
    _rng: random.Random = field(init=False)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.seed)
        self.project = Project(
            id=ProjectId(self._id(IdKind.PROJECT)),
            title="Lineage fixture",
            is_synthetic=False,
            created_at=DEMO_TIME,
        )

    def _id(self, kind: IdKind) -> str:
        return make_id(kind, f"{self._rng.getrandbits(128):032x}")

    def revision(
        self,
        symbols: dict[tuple[str, str], int | None],
        *,
        indexed: bool = True,
        issues: tuple[str, ...] = (),
        algorithm: object = _AUTO,
    ) -> dict[tuple[str, str], CodeSymbol]:
        sequence = len(self.revisions) + 1
        revision = WorkspaceRevision(
            id=RevisionId(self._id(IdKind.WORKSPACE_REVISION)),
            project_id=self.project.id,
            sequence=sequence,
            vcs_ref=None,
            symbols_indexed=indexed,
            recorded_at=DEMO_TIME + timedelta(seconds=sequence),
            file_issues=tuple(
                FileIssue(path, FileIssueKind.SYNTAX_ERROR) for path in sorted(issues)
            ),
        )
        self.revisions.append(revision)
        created: dict[tuple[str, str], CodeSymbol] = {}
        for (path, name), value in symbols.items():
            chosen = ALGORITHM if algorithm is _AUTO else algorithm
            created[(path, name)] = CodeSymbol(
                id=SymbolId(self._id(IdKind.SYMBOL)),
                project_id=self.project.id,
                revision_id=revision.id,
                language=Language.PYTHON,
                kind=SymbolKind.METHOD if "." in name else SymbolKind.FUNCTION,
                qualified_name=name,
                file_path=path,
                span=None,
                fingerprint=None if value is None else fingerprint(value),
                fingerprint_algorithm=None if value is None else chosen,  # type: ignore[arg-type]
            )
        self.symbols.extend(created.values())
        return created

    def graph(self) -> ProvenanceGraph:
        return ProvenanceGraph(
            self.project,
            1,
            revisions=tuple(self.revisions),
            symbols=tuple(self.symbols),
        )

    def trace(self, symbol: CodeSymbol) -> SymbolTrace:
        return trace_symbol(self.graph(), symbol.id)


def _reason(history: History, symbol: CodeSymbol) -> FreshnessReason:
    return history.trace(symbol).reason


# ---------------------------------------------------------------------- one test per reason


def test_unchanged() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    second = history.revision({(A, "f"): 1})[(A, "f")]
    trace = history.trace(first)
    assert (trace.reason, trace.freshness) == (FreshnessReason.UNCHANGED, LinkFreshness.CURRENT)
    assert trace.current == second
    assert trace.successors == (second.id,)
    assert not trace.relocated
    assert trace.evaluated_revision == history.revisions[-1]


def test_relocated() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    second = history.revision({(A, "g"): 1})[(A, "g")]
    trace = history.trace(first)
    assert (trace.reason, trace.freshness) == (FreshnessReason.RELOCATED, LinkFreshness.MOVED)
    assert trace.current == second
    assert trace.relocated


def test_content_changed() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    history.revision({(A, "f"): 2})
    trace = history.trace(first)
    assert (trace.reason, trace.freshness) == (
        FreshnessReason.CONTENT_CHANGED,
        LinkFreshness.STALE,
    )


def test_removed() -> None:
    history = History()
    first = history.revision({(A, "f"): 1, (A, "g"): 2})[(A, "f")]
    history.revision({(A, "g"): 2})
    trace = history.trace(first)
    assert (trace.reason, trace.freshness) == (FreshnessReason.REMOVED, LinkFreshness.ORPHANED)
    assert trace.lost_in_revision == history.revisions[1]
    assert trace.current is None
    assert trace.last_seen == first
    assert trace.candidates == ()


def test_ambiguous_relocation() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    second = history.revision({(A, "h"): 1, (A, "g"): 1})
    trace = history.trace(first)
    assert (trace.reason, trace.freshness) == (
        FreshnessReason.AMBIGUOUS_RELOCATION,
        LinkFreshness.ORPHANED,
    )
    assert trace.candidates == (second[(A, "g")], second[(A, "h")])
    assert trace.lost_in_revision == history.revisions[1]


def test_candidates_are_capped() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    history.revision({(A, f"g{index:02d}"): 1 for index in range(MAX_CANDIDATES + 3)})
    trace = history.trace(first)
    assert len(trace.candidates) == MAX_CANDIDATES
    assert [item.qualified_name for item in trace.candidates] == [
        f"g{index:02d}" for index in range(MAX_CANDIDATES)
    ]


def test_not_fingerprinted() -> None:
    history = History()
    first = history.revision({(A, "f"): None})[(A, "f")]
    history.revision({(A, "f"): None})
    trace = history.trace(first)
    assert (trace.reason, trace.freshness) == (
        FreshnessReason.NOT_FINGERPRINTED,
        LinkFreshness.UNKNOWN,
    )
    assert len(trace.successors) == 1
    later = History()
    origin = later.revision({(A, "f"): 1})[(A, "f")]
    later.revision({(A, "f"): None})
    assert _reason(later, origin) is FreshnessReason.NOT_FINGERPRINTED
    gone = History()
    origin = gone.revision({(A, "f"): None})[(A, "f")]
    gone.revision({})
    trace = gone.trace(origin)
    assert trace.reason is FreshnessReason.NOT_FINGERPRINTED
    assert trace.lost_in_revision is None


def test_not_indexed() -> None:
    history = History()
    first = history.revision({(A, "f"): 1}, indexed=False)[(A, "f")]
    trace = history.trace(first)
    assert (trace.reason, trace.freshness) == (FreshnessReason.NOT_INDEXED, LinkFreshness.UNKNOWN)
    assert trace.evaluated_revision is None
    assert trace.current is None
    unfingerprinted = history.revision({(A, "g"): None}, indexed=False)[(A, "g")]
    trace = history.trace(unfingerprinted)
    assert trace.reason is FreshnessReason.NOT_FINGERPRINTED
    assert trace.evaluated_revision is None


def test_file_not_parsed() -> None:
    history = History()
    first = history.revision({(A, "f"): 1, (B, "g"): 2})[(A, "f")]
    history.revision({(B, "g"): 2}, issues=(A,))
    trace = history.trace(first)
    assert (trace.reason, trace.freshness) == (
        FreshnessReason.FILE_NOT_PARSED,
        LinkFreshness.UNKNOWN,
    )
    assert trace.last_seen == first
    assert trace.current is None
    assert trace.lost_in_revision is None


def test_algorithm_changed() -> None:
    history = History()
    first = history.revision({(A, "f"): 1}, algorithm=None)[(A, "f")]
    history.revision({(A, "f"): 1})
    trace = history.trace(first)
    assert (trace.reason, trace.freshness) == (
        FreshnessReason.ALGORITHM_CHANGED,
        LinkFreshness.UNKNOWN,
    )


def test_relocated_and_changed() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    history.revision({(A, "g"): 1})
    third = history.revision({(A, "g"): 2})[(A, "g")]
    trace = history.trace(first)
    assert (trace.reason, trace.freshness) == (
        FreshnessReason.RELOCATED_AND_CHANGED,
        LinkFreshness.STALE,
    )
    assert trace.current == third
    assert trace.relocated


def test_every_reason_maps_to_a_freshness() -> None:
    assert set(FRESHNESS_OF_REASON) == set(FreshnessReason)
    with pytest.raises(TypeError):
        FRESHNESS_OF_REASON[FreshnessReason.REMOVED] = LinkFreshness.CURRENT  # type: ignore[index]


# ---------------------------------------------------------------------- M1 fixture


@pytest.fixture(scope="module")
def complete() -> tuple[ProvenanceGraph, CompleteProject]:
    service = make_service()
    names = build_complete_real_project(service)
    return service.load(names.project), names


def test_m1_fixture_still_gives_current_stale_moved_and_orphaned(
    complete: tuple[ProvenanceGraph, CompleteProject],
) -> None:
    graph, names = complete
    lineage = SymbolLineage(graph)
    expected = {
        names.link_current: (LinkFreshness.CURRENT, FreshnessReason.UNCHANGED),
        names.link_stale: (LinkFreshness.STALE, FreshnessReason.CONTENT_CHANGED),
        names.link_moved: (LinkFreshness.MOVED, FreshnessReason.RELOCATED),
        names.link_orphaned: (LinkFreshness.ORPHANED, FreshnessReason.REMOVED),
    }
    for link_id, (freshness, reason) in expected.items():
        link = graph.get(ImplementationLink, link_id)
        trace = lineage.resolve(link)
        assert (trace.freshness, trace.reason) == (freshness, reason)
        assert link_freshness(graph, link) is freshness
    moved = lineage.trace(names.symbol_moved)
    assert moved.current is not None
    assert moved.current.file_path == "src/reco/calibration.py"
    assert lineage.trace(names.symbol_moved) is moved  # memoized
    with pytest.raises(RecordNotFoundError):
        lineage.trace(names.link_current)


# ---------------------------------------------------------------------- scenarios


def test_edit_then_revert_is_current() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    history.revision({(A, "f"): 2})
    history.revision({(A, "f"): 1})
    assert _reason(history, first) is FreshnessReason.UNCHANGED


def test_rename_then_edit_is_stale_relocated() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    history.revision({(A, "g"): 1})
    history.revision({(A, "g"): 3})
    trace = history.trace(first)
    assert trace.reason is FreshnessReason.RELOCATED_AND_CHANGED
    assert trace.current is not None and trace.current.qualified_name == "g"


def test_rename_and_edit_in_one_revision_is_removed() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    history.revision({(A, "g"): 2})
    assert _reason(history, first) is FreshnessReason.REMOVED


def test_new_symbol_reusing_a_renamed_name_does_not_inherit() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    renamed = history.revision({(A, "g"): 1})[(A, "g")]
    third = history.revision({(A, "g"): 1, (A, "f"): 9})
    graph = history.graph()
    lineage = SymbolLineage(graph)
    trace = lineage.trace(first.id)
    assert trace.reason is FreshnessReason.RELOCATED
    assert trace.current == third[(A, "g")]
    assert trace.successors == (renamed.id, third[(A, "g")].id)
    assert not lineage.related(first.id, third[(A, "f")].id)
    assert lineage.trace(third[(A, "f")].id).reason is FreshnessReason.UNCHANGED


def test_rename_chain_follows_to_last() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    history.revision({(A, "g"): 1})
    history.revision({(A, "h"): 1})
    last = history.revision({(A, "C.h"): 1})[(A, "C.h")]
    trace = history.trace(first)
    assert trace.reason is FreshnessReason.RELOCATED
    assert trace.current == last
    assert len(trace.successors) == 3


def test_rename_and_file_move_in_one_step_is_removed() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    history.revision({(B, "g"): 1})
    trace = history.trace(first)
    assert trace.reason is FreshnessReason.REMOVED
    assert trace.candidates == ()


def test_file_move_under_the_same_name_is_moved() -> None:
    history = History()
    first = history.revision({(A, "C.fit"): 1})[(A, "C.fit")]
    moved = history.revision({(B, "fit"): 1})[(B, "fit")]
    trace = history.trace(first)
    assert trace.reason is FreshnessReason.RELOCATED
    assert trace.current == moved


def test_move_into_class_same_file_is_moved_when_identical() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    moved = history.revision({(A, "C.g"): 1})[(A, "C.g")]
    trace = history.trace(first)
    assert trace.reason is FreshnessReason.RELOCATED
    assert trace.current == moved


def test_preexisting_twin_is_never_a_target() -> None:
    history = History()
    first = history.revision({(A, "f"): 1, (A, "twin"): 1})[(A, "f")]
    history.revision({(A, "twin"): 1})
    trace = history.trace(first)
    assert trace.reason is FreshnessReason.REMOVED
    assert trace.candidates == ()


def test_two_new_candidates_are_ambiguous() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    created = history.revision({(A, "g"): 1, (B, "f"): 1})
    trace = history.trace(first)
    assert trace.reason is FreshnessReason.AMBIGUOUS_RELOCATION
    assert set(trace.candidates) == set(created.values())


def test_one_candidate_with_a_rival_is_ambiguous() -> None:
    history = History()
    first = history.revision({(A, "f"): 1, (A, "k"): 1})[(A, "f")]
    created = history.revision({(A, "g"): 1})
    trace = history.trace(first)
    assert trace.reason is FreshnessReason.AMBIGUOUS_RELOCATION
    assert trace.candidates == (created[(A, "g")],)


def test_file_issue_carries_symbols_and_reports_file_not_parsed() -> None:
    history = History()
    first = history.revision({(A, "f"): 1, (B, "g"): 2})[(A, "f")]
    history.revision({(B, "g"): 2}, issues=(A,))
    history.revision({(B, "g"): 2}, issues=(A,))
    trace = history.trace(first)
    assert trace.reason is FreshnessReason.FILE_NOT_PARSED
    assert trace.successors == ()


def test_recovery_after_file_issue_is_not_treated_as_new() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    elsewhere = history.revision({(B, "f"): 1}, issues=(A,))[(B, "f")]
    recovered = history.revision({(A, "f"): 1})[(A, "f")]
    trace = history.trace(first)
    assert trace.reason is FreshnessReason.UNCHANGED
    assert trace.current == recovered
    # The recovered symbol is not new, so the vanished twin cannot move onto it.
    assert _reason(history, elsewhere) is FreshnessReason.REMOVED


def test_symbol_from_an_issue_file_that_never_returns_is_removed() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    history.revision({}, issues=(A,))
    history.revision({})
    trace = history.trace(first)
    assert trace.reason is FreshnessReason.REMOVED
    assert trace.lost_in_revision == history.revisions[2]


def test_unindexed_revisions_attach_by_key_only() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    unindexed = history.revision({(A, "f"): 2, (A, "g"): 1}, indexed=False)
    trace = history.trace(first)
    assert trace.reason is FreshnessReason.UNCHANGED
    assert trace.current == first
    assert trace.successors == (unindexed[(A, "f")].id,)
    third = history.revision({(A, "f"): 1})[(A, "f")]
    graph = history.graph()
    lineage = SymbolLineage(graph)
    assert lineage.trace(first.id).successors == (unindexed[(A, "f")].id, third.id)
    assert lineage.related(unindexed[(A, "f")].id, first.id)
    assert not lineage.related(unindexed[(A, "g")].id, first.id)
    assert lineage.trace(unindexed[(A, "f")].id).reason is FreshnessReason.CONTENT_CHANGED
    assert lineage.trace(unindexed[(A, "g")].id).reason is FreshnessReason.REMOVED


def test_algorithm_change_is_unknown() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    history.revision({(A, "f"): 1}, algorithm=None)
    trace = history.trace(first)
    assert trace.reason is FreshnessReason.ALGORITHM_CHANGED
    assert trace.freshness is LinkFreshness.UNKNOWN


def test_origin_in_unindexed_revision_without_indexed_successor_is_not_indexed() -> None:
    history = History()
    history.revision({(A, "f"): 1})
    origin = history.revision({(A, "f"): 1}, indexed=False)[(A, "f")]
    trace = history.trace(origin)
    assert trace.reason is FreshnessReason.NOT_INDEXED
    assert trace.evaluated_revision is None
    assert trace.successors == ()


def test_moved_symbol_keeps_moving_through_an_unindexed_revision() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    history.revision({(A, "g"): 1}, indexed=False)
    moved = history.revision({(A, "g"): 1})[(A, "g")]
    trace = history.trace(first)
    assert trace.reason is FreshnessReason.RELOCATED
    assert trace.current == moved
    assert trace.successors == (moved.id,)


def test_trace_invariants_reject_inconsistent_combinations() -> None:
    history = History()
    first = history.revision({(A, "f"): 1})[(A, "f")]
    moved = history.revision({(A, "g"): 1})[(A, "g")]
    revision = history.revisions[-1]
    valid = SymbolTrace(
        origin=first,
        freshness=LinkFreshness.MOVED,
        reason=FreshnessReason.RELOCATED,
        last_seen=moved,
        evaluated_revision=revision,
        lost_in_revision=None,
        candidates=(),
        successors=(moved.id,),
    )
    cases = [
        (replace, {"freshness": LinkFreshness.CURRENT}, "R.trace.freshness"),
        (replace, {"last_seen": first}, "R.trace.current"),
        (
            replace,
            {"reason": FreshnessReason.UNCHANGED, "freshness": LinkFreshness.CURRENT},
            "R.trace.key",
        ),
        (replace, {"lost_in_revision": revision}, "R.trace.lost"),
        (replace, {"candidates": (moved,)}, "R.trace.candidates"),
        (
            replace,
            {
                "reason": FreshnessReason.NOT_INDEXED,
                "freshness": LinkFreshness.UNKNOWN,
            },
            "R.trace.evaluated",
        ),
        (
            replace,
            {
                "reason": FreshnessReason.FILE_NOT_PARSED,
                "freshness": LinkFreshness.UNKNOWN,
                "evaluated_revision": None,
            },
            "R.trace.evaluated",
        ),
        (
            replace,
            {
                "reason": FreshnessReason.AMBIGUOUS_RELOCATION,
                "freshness": LinkFreshness.ORPHANED,
                "lost_in_revision": revision,
            },
            "R.trace.candidates",
        ),
        (
            replace,
            {
                "reason": FreshnessReason.REMOVED,
                "freshness": LinkFreshness.ORPHANED,
                "lost_in_revision": revision,
                "candidates": (moved,) * (MAX_CANDIDATES + 1),
            },
            "R.trace.candidates",
        ),
    ]
    for change, values, rule in cases:
        with pytest.raises(ProvenanceInvariantError) as error:
            change(valid, **values)
        assert error.value.rule == rule, values
    unchanged_key = replace(
        valid,
        origin=moved,
        reason=FreshnessReason.CONTENT_CHANGED,
        freshness=LinkFreshness.STALE,
    )
    assert unchanged_key.current == moved
    with pytest.raises(ProvenanceInvariantError) as error:
        replace(valid, origin=moved)
    assert error.value.rule == "R.trace.key"


def test_related_is_symmetric() -> None:
    history = History()
    history.revision({(A, "f"): 1, (A, "x"): 5})
    history.revision({(A, "g"): 1, (A, "x"): 6}, indexed=False)
    history.revision({(A, "g"): 1, (B, "x"): 6})
    graph = history.graph()
    lineage = SymbolLineage(graph)
    ids = [symbol.id for symbol in graph.symbols]
    for left in ids:
        for right in ids:
            assert lineage.related(left, right) == lineage.related(right, left)
        assert lineage.related(left, left)


# ---------------------------------------------------------------------- properties

NAMES = ("f", "g", "h", "C.f", "C.k")
FILES = (A, B)

operation_strategy = st.one_of(
    st.tuples(st.just("add"), st.sampled_from(FILES), st.sampled_from(NAMES)),
    st.tuples(st.just("rename"), st.integers(0, 20), st.sampled_from(NAMES)),
    st.tuples(st.just("move"), st.integers(0, 20), st.sampled_from(FILES)),
    st.tuples(st.just("edit"), st.integers(0, 20)),
    st.tuples(st.just("delete"), st.integers(0, 20)),
    st.tuples(st.just("issue"), st.sampled_from(FILES)),
    st.tuples(st.just("unindexed"), st.integers(0, 20)),
    st.tuples(st.just("twin"), st.integers(0, 20), st.sampled_from(NAMES)),
)


def _apply(
    state: dict[tuple[str, str], int],
    operation: tuple[object, ...],
    counter: list[int],
) -> tuple[dict[tuple[str, str], int], bool, tuple[str, ...]]:
    state = dict(state)
    kind = operation[0]
    keys = sorted(state)
    if kind == "add":
        counter[0] += 1
        state.setdefault((str(operation[1]), str(operation[2])), counter[0])
        return state, True, ()
    if kind == "issue":
        return state, True, (str(operation[1]),)
    if not keys:
        return state, kind != "unindexed", ()
    key = keys[int(operation[1]) % len(keys)]  # type: ignore[call-overload]
    if kind == "rename":
        state[(key[0], str(operation[2]))] = state.pop(key)
    elif kind == "move":
        state[(str(operation[2]), key[1])] = state.pop(key)
    elif kind == "edit":
        counter[0] += 1
        state[key] = counter[0]
    elif kind == "delete":
        del state[key]
    elif kind == "twin":
        state.setdefault((key[0], str(operation[2])), state[key])
    return state, kind != "unindexed", ()


def _build(operations: list[tuple[object, ...]], seed: int) -> History:
    history = History(seed=seed)
    state: dict[tuple[str, str], int] = {}
    counter = [0]
    for operation in operations:
        state, indexed, issues = _apply(state, operation, counter)
        visible = {key: value for key, value in state.items() if key[0] not in issues}
        history.revision(dict(visible), indexed=indexed, issues=issues)
    return history


@settings(max_examples=150, deadline=None)
@given(st.lists(operation_strategy, min_size=1, max_size=8))
def test_random_histories_are_sound(operations: list[tuple[object, ...]]) -> None:
    graph = _build(operations, seed=1).graph()
    lineage = SymbolLineage(graph)
    for symbol in graph.symbols:
        trace = lineage.trace(symbol.id)
        assert trace.freshness is FRESHNESS_OF_REASON[trace.reason]
        current = trace.current
        if trace.freshness is LinkFreshness.CURRENT:
            assert current is not None
            assert current.key == symbol.key
            assert current.fingerprint == symbol.fingerprint
        elif trace.freshness is LinkFreshness.MOVED:
            assert current is not None
            assert current.key != symbol.key
            assert current.fingerprint == symbol.fingerprint
        elif trace.freshness is LinkFreshness.STALE:
            assert current is not None
            assert current.fingerprint != symbol.fingerprint
        elif trace.freshness is LinkFreshness.ORPHANED:
            assert trace.lost_in_revision is not None
            assert trace.current is None
        sequences = [graph.get(CodeSymbol, item).revision_id for item in trace.successors]
        ordered = [
            next(r.sequence for r in graph.revisions if r.id == revision_id)
            for revision_id in sequences
        ]
        assert ordered == sorted(set(ordered))


def _describe(graph: ProvenanceGraph, trace: SymbolTrace) -> tuple[object, ...]:
    def sequence(revision_id: str) -> int:
        return next(item.sequence for item in graph.revisions if item.id == revision_id)

    def where(symbol: CodeSymbol) -> tuple[object, ...]:
        return (symbol.key, sequence(symbol.revision_id), symbol.fingerprint)

    return (
        where(trace.origin),
        trace.freshness,
        trace.reason,
        where(trace.last_seen),
        None if trace.evaluated_revision is None else trace.evaluated_revision.sequence,
        None if trace.lost_in_revision is None else trace.lost_in_revision.sequence,
        tuple(where(item) for item in trace.candidates),
        tuple(where(graph.get(CodeSymbol, item)) for item in trace.successors),
    )


@settings(max_examples=60, deadline=None)
@given(
    st.lists(operation_strategy, min_size=1, max_size=7),
    st.integers(min_value=1, max_value=2**32),
)
def test_results_invariant_under_id_permutation(
    operations: list[tuple[object, ...]], seed: int
) -> None:
    first = _build(operations, seed=0).graph()
    second = _build(operations, seed=seed).graph()
    first_lineage = SymbolLineage(first)
    second_lineage = SymbolLineage(second)

    def described(graph: ProvenanceGraph, lineage: SymbolLineage) -> set[tuple[object, ...]]:
        return {_describe(graph, lineage.trace(symbol.id)) for symbol in graph.symbols}

    assert described(first, first_lineage) == described(second, second_lineage)
