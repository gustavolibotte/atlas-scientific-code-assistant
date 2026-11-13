"""Symbol lineage across workspace revisions and the freshness of implementation links.

A link names one symbol snapshot (the *origin*). Its lineage follows the symbol forward
through every later revision: by key while the key exists, through a file that could not
be parsed by carrying its last known symbols forward, and across a rename or move only
when exactly one plausible new symbol has an equal fingerprint and no other disappeared
symbol shares it. Results depend only on keys, sequences and fingerprints, never on
record identifiers or tuple order.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from asca.domain.provenance.code import (
    CodeSymbol,
    FingerprintAlgorithm,
    ImplementationLink,
    Language,
    LinkFreshness,
    SymbolKey,
    WorkspaceRevision,
)
from asca.domain.provenance.errors import ProvenanceInvariantError
from asca.domain.provenance.ids import RevisionId, SymbolId

if TYPE_CHECKING:
    from asca.domain.provenance.graph import ProvenanceGraph


class FreshnessReason(StrEnum):
    UNCHANGED = "unchanged"
    RELOCATED = "relocated"
    CONTENT_CHANGED = "content_changed"
    RELOCATED_AND_CHANGED = "relocated_and_changed"
    REMOVED = "removed"
    AMBIGUOUS_RELOCATION = "ambiguous_relocation"
    NOT_FINGERPRINTED = "not_fingerprinted"
    NOT_INDEXED = "not_indexed"
    FILE_NOT_PARSED = "file_not_parsed"
    ALGORITHM_CHANGED = "algorithm_changed"


FRESHNESS_OF_REASON: Final[Mapping[FreshnessReason, LinkFreshness]] = MappingProxyType(
    {
        FreshnessReason.UNCHANGED: LinkFreshness.CURRENT,
        FreshnessReason.RELOCATED: LinkFreshness.MOVED,
        FreshnessReason.CONTENT_CHANGED: LinkFreshness.STALE,
        FreshnessReason.RELOCATED_AND_CHANGED: LinkFreshness.STALE,
        FreshnessReason.REMOVED: LinkFreshness.ORPHANED,
        FreshnessReason.AMBIGUOUS_RELOCATION: LinkFreshness.ORPHANED,
        FreshnessReason.NOT_FINGERPRINTED: LinkFreshness.UNKNOWN,
        FreshnessReason.NOT_INDEXED: LinkFreshness.UNKNOWN,
        FreshnessReason.FILE_NOT_PARSED: LinkFreshness.UNKNOWN,
        FreshnessReason.ALGORITHM_CHANGED: LinkFreshness.UNKNOWN,
    }
)
MAX_CANDIDATES = 10

_SAME_KEY = frozenset({FreshnessReason.UNCHANGED, FreshnessReason.CONTENT_CHANGED})
_RELOCATED = frozenset({FreshnessReason.RELOCATED, FreshnessReason.RELOCATED_AND_CHANGED})
_HAS_CURRENT = frozenset({LinkFreshness.CURRENT, LinkFreshness.MOVED, LinkFreshness.STALE})
_WITHOUT_EVALUATION = frozenset({FreshnessReason.NOT_INDEXED, FreshnessReason.NOT_FINGERPRINTED})

_Group = tuple[Language, tuple[FingerprintAlgorithm | None, str]]


def _fail(rule: str, detail: str) -> ProvenanceInvariantError:
    return ProvenanceInvariantError(rule, detail)


@dataclass(frozen=True, slots=True)
class SymbolTrace:
    """Where the symbol a link names went, and how fresh the link therefore is."""

    origin: CodeSymbol
    freshness: LinkFreshness
    reason: FreshnessReason
    last_seen: CodeSymbol
    evaluated_revision: WorkspaceRevision | None
    lost_in_revision: WorkspaceRevision | None
    candidates: tuple[CodeSymbol, ...]
    successors: tuple[SymbolId, ...]

    def __post_init__(self) -> None:
        if FRESHNESS_OF_REASON.get(self.reason) is not self.freshness:
            raise _fail("R.trace.freshness", "freshness does not match the reason")
        current = self.current
        if self.freshness in _HAS_CURRENT and current is None:
            raise _fail("R.trace.current", "a current, moved or stale trace needs a current symbol")
        if self.reason in _SAME_KEY and (current is None or current.key != self.origin.key):
            raise _fail("R.trace.key", "an unrelocated trace keeps the origin key")
        if self.reason in _RELOCATED and (current is None or current.key == self.origin.key):
            raise _fail("R.trace.key", "a relocated trace changes the origin key")
        if (self.freshness is LinkFreshness.ORPHANED) != (self.lost_in_revision is not None):
            raise _fail("R.trace.lost", "lost_in_revision is set exactly for orphaned links")
        ambiguous = self.reason is FreshnessReason.AMBIGUOUS_RELOCATION
        if bool(self.candidates) != ambiguous or len(self.candidates) > MAX_CANDIDATES:
            raise _fail("R.trace.candidates", "candidates belong to an ambiguous relocation")
        if self.reason is FreshnessReason.NOT_INDEXED and self.evaluated_revision is not None:
            raise _fail("R.trace.evaluated", "a not-indexed trace has no evaluated revision")
        if self.evaluated_revision is None and self.reason not in _WITHOUT_EVALUATION:
            raise _fail("R.trace.evaluated", "this reason needs an evaluated revision")

    @property
    def current(self) -> CodeSymbol | None:
        """last_seen when it belongs to the evaluated revision and the link is not orphaned."""
        evaluated = self.evaluated_revision
        if (
            evaluated is None
            or self.last_seen.revision_id != evaluated.id
            or self.freshness is LinkFreshness.ORPHANED
        ):
            return None
        return self.last_seen

    @property
    def relocated(self) -> bool:
        return self.reason in _RELOCATED


def _group_of(symbol: CodeSymbol) -> _Group | None:
    key = symbol.fingerprint_key
    return None if key is None else (symbol.language, key)


def _last_segment(qualified_name: str) -> str:
    return qualified_name.rsplit(".", 1)[-1]


def _plausible(current: CodeSymbol, candidate: CodeSymbol) -> bool:
    return candidate.file_path == current.file_path or _last_segment(
        candidate.qualified_name
    ) == _last_segment(current.qualified_name)


def _grouped(symbols: list[CodeSymbol]) -> dict[_Group, list[CodeSymbol]]:
    groups: dict[_Group, list[CodeSymbol]] = {}
    for symbol in symbols:
        group = _group_of(symbol)
        if group is not None:
            groups.setdefault(group, []).append(symbol)
    return groups


class SymbolLineage:
    """Precomputed per-revision symbol maps of one graph; traces are memoized."""

    __slots__ = (
        "_by_key",
        "_effective",
        "_gone",
        "_graph",
        "_memo",
        "_new",
        "latest_indexed",
        "revisions",
    )

    def __init__(self, graph: "ProvenanceGraph") -> None:
        self._graph = graph
        self.revisions: tuple[WorkspaceRevision, ...] = tuple(
            sorted(graph.revisions, key=lambda revision: revision.sequence)
        )
        self._by_key: dict[RevisionId, dict[SymbolKey, CodeSymbol]] = {
            revision.id: {} for revision in self.revisions
        }
        for symbol in graph.symbols:
            self._by_key[symbol.revision_id][symbol.key] = symbol
        self._effective: dict[RevisionId, dict[SymbolKey, CodeSymbol]] = {}
        self._new: dict[RevisionId, dict[_Group, list[CodeSymbol]]] = {}
        self._gone: dict[RevisionId, dict[_Group, list[CodeSymbol]]] = {}
        previous: dict[SymbolKey, CodeSymbol] = {}
        latest: WorkspaceRevision | None = None
        for revision in self.revisions:
            if not revision.symbols_indexed:
                continue
            own = self._by_key[revision.id]
            effective = dict(own)
            issue_paths = revision.issue_paths
            for key, symbol in previous.items():
                if key[1] in issue_paths and key not in effective:
                    effective[key] = symbol
            self._effective[revision.id] = effective
            self._new[revision.id] = _grouped(
                [symbol for key, symbol in own.items() if key not in previous]
            )
            self._gone[revision.id] = _grouped(
                [symbol for key, symbol in previous.items() if key not in effective]
            )
            previous = effective
            latest = revision
        self.latest_indexed: WorkspaceRevision | None = latest
        self._memo: dict[str, SymbolTrace] = {}

    def resolve(self, link: ImplementationLink) -> SymbolTrace:
        return self.trace(link.symbol_id)

    def related(self, a: str, b: str) -> bool:
        """True when ``a`` and ``b`` are the same symbol or one follows the other."""
        return a == b or b in self.trace(a).successors or a in self.trace(b).successors

    def trace(self, symbol_id: str) -> SymbolTrace:
        """Raise ``RecordNotFoundError`` for an unknown symbol id."""
        cached = self._memo.get(symbol_id)
        if cached is None:
            cached = self._trace(self._graph.get(CodeSymbol, symbol_id))
            self._memo[symbol_id] = cached
        return cached

    def _trace(self, origin: CodeSymbol) -> SymbolTrace:
        start = self._graph.get(WorkspaceRevision, origin.revision_id).sequence
        current = origin
        successors: list[SymbolId] = []
        lost: WorkspaceRevision | None = None
        candidates: tuple[CodeSymbol, ...] = ()
        for revision in self.revisions:
            if revision.sequence <= start:
                continue
            if not revision.symbols_indexed:
                attached = self._by_key[revision.id].get(current.key)
                if attached is not None:
                    successors.append(attached.id)
                continue
            found = self._effective[revision.id].get(current.key)
            if found is not None:
                if found.revision_id == revision.id:
                    current = found
                    successors.append(found.id)
                continue
            group = _group_of(current)
            if group is None:
                lost = revision
                break
            plausible = [
                item for item in self._new[revision.id].get(group, ()) if _plausible(current, item)
            ]
            rivals = [
                item for item in self._gone[revision.id].get(group, ()) if item.key != current.key
            ]
            if len(plausible) == 1 and not rivals:
                current = plausible[0]
                successors.append(current.id)
                continue
            lost = revision
            candidates = tuple(sorted(plausible, key=lambda item: item.key))[:MAX_CANDIDATES]
            break

        latest = self.latest_indexed
        evaluated = latest if latest is not None and latest.sequence >= start else None
        reason = self._reason(origin, current, evaluated, lost, candidates)
        orphaned = FRESHNESS_OF_REASON[reason] is LinkFreshness.ORPHANED
        return SymbolTrace(
            origin=origin,
            freshness=FRESHNESS_OF_REASON[reason],
            reason=reason,
            last_seen=current,
            evaluated_revision=evaluated,
            lost_in_revision=lost if orphaned else None,
            candidates=candidates if reason is FreshnessReason.AMBIGUOUS_RELOCATION else (),
            successors=tuple(successors),
        )

    @staticmethod
    def _reason(
        origin: CodeSymbol,
        current: CodeSymbol,
        evaluated: WorkspaceRevision | None,
        lost: WorkspaceRevision | None,
        candidates: tuple[CodeSymbol, ...],
    ) -> FreshnessReason:
        if origin.fingerprint is None:
            return FreshnessReason.NOT_FINGERPRINTED
        if evaluated is None:
            return FreshnessReason.NOT_INDEXED
        if lost is not None:
            if candidates:
                return FreshnessReason.AMBIGUOUS_RELOCATION
            return FreshnessReason.REMOVED
        if current.revision_id != evaluated.id:
            return FreshnessReason.FILE_NOT_PARSED
        if current.fingerprint is None:
            return FreshnessReason.NOT_FINGERPRINTED
        if current.fingerprint_algorithm != origin.fingerprint_algorithm:
            return FreshnessReason.ALGORITHM_CHANGED
        same_key = current.key == origin.key
        if current.fingerprint == origin.fingerprint:
            return FreshnessReason.UNCHANGED if same_key else FreshnessReason.RELOCATED
        if same_key:
            return FreshnessReason.CONTENT_CHANGED
        return FreshnessReason.RELOCATED_AND_CHANGED


def trace_symbol(graph: "ProvenanceGraph", symbol_id: str) -> SymbolTrace:
    return SymbolLineage(graph).trace(symbol_id)
