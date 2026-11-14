"""Federated search over knowledge providers.

Every configured provider is reported, never hidden. Candidates are grouped by shared
identity PIDs with a union-find; an uncertain component is split instead of merged, and
fields are never fused. The result is deterministic: it never depends on completion order
or input order. There is no cache.
"""

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, TypeVar

from asca.application.knowledge.models import (
    PUBLIC_NETWORK_KINDS,
    CandidateRef,
    FetchOutcome,
    FetchResult,
    HealthState,
    KnowledgeCandidate,
    KnowledgeQuery,
    ProviderDescriptor,
    ProviderError,
    ProviderErrorKind,
    ProviderHealth,
    ProviderKind,
    SearchOutcome,
    SearchResult,
)
from asca.application.knowledge.pids import pid_sort_key, pid_text
from asca.application.knowledge.policy import AuthoritySuggestion, suggest_authority
from asca.application.ports import KnowledgeProvider
from asca.domain.provenance import AccessClass, PersistentIdentifier, PidScheme, most_restrictive

MAX_PROVIDERS: Final = 16
T = TypeVar("T")


class ProviderStatus(StrEnum):
    OK = "ok"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class GroupFlag(StrEnum):
    AMBIGUOUS_IDENTITY = "ambiguous_identity"
    MULTIPLE_DOIS = "multiple_dois"
    ACCESS_MIXED = "access_mixed"


def _number(value: object, low: float, high: float) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool) and low <= value <= high


@dataclass(frozen=True, slots=True)
class FederationPolicy:
    live: bool
    precedence: tuple[str, ...] = ()
    """Empty: providers in construction order."""
    grace_s: float = 3.0
    """Outer timeout = descriptor.timeout_s + grace_s."""
    max_parallel: int = 8
    max_groups: int = 50

    def __post_init__(self) -> None:
        if not isinstance(self.live, bool):
            raise ValueError("policy.live must be a bool")
        if not isinstance(self.precedence, tuple) or not all(
            isinstance(item, str) for item in self.precedence
        ):
            raise ValueError("policy.precedence must be a tuple of provider ids")
        if not _number(self.grace_s, 0.0, 10.0):
            raise ValueError("policy.grace_s must be between 0 and 10 seconds")
        if not isinstance(self.max_parallel, int) or not _number(self.max_parallel, 1, 16):
            raise ValueError("policy.max_parallel must be between 1 and 16")
        if not isinstance(self.max_groups, int) or not _number(self.max_groups, 1, 200):
            raise ValueError("policy.max_groups must be between 1 and 200")


_REPORTED_OK: Final = frozenset({ProviderStatus.OK, ProviderStatus.PARTIAL})


@dataclass(frozen=True, slots=True)
class ProviderReport:
    provider_id: str
    kind: ProviderKind
    status: ProviderStatus
    returned: int
    dropped_items: int
    total_reported: int | None
    error: ProviderError | None
    """None exactly when the status is OK or PARTIAL."""
    elapsed_ms: int
    """Excluded from JSON output by default."""

    def __post_init__(self) -> None:
        if (self.error is None) != (self.status in _REPORTED_OK):
            raise ValueError("report.error is required exactly when the provider failed")
        for name in ("returned", "dropped_items", "elapsed_ms"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"report.{name} must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class AssessedCandidate:
    candidate: KnowledgeCandidate
    suggestion: AuthoritySuggestion


@dataclass(frozen=True, slots=True)
class EvidenceGroup:
    key: str
    identity_pids: tuple[PersistentIdentifier, ...]
    """Sorted union of the members' identity pids."""
    members: tuple[AssessedCandidate, ...]
    """Sorted by (precedence index, rank)."""
    flags: frozenset[GroupFlag]
    effective_access_class: AccessClass
    """The most restrictive member access class (ADR 0038 section 6)."""
    best_rank: int


@dataclass(frozen=True, slots=True)
class FederatedSearchResult:
    query: KnowledgeQuery
    groups: tuple[EvidenceGroup, ...]
    reports: tuple[ProviderReport, ...]
    """One per configured provider (enabled and disabled), in precedence order."""

    @property
    def complete(self) -> bool:
        return all(report.status is ProviderStatus.OK for report in self.reports)

    @property
    def not_consulted(self) -> tuple[ProviderReport, ...]:
        return tuple(
            report
            for report in self.reports
            if report.status in (ProviderStatus.FAILED, ProviderStatus.SKIPPED)
        )


# ---------------------------------------------------------------------- grouping


def _node_key(item: AssessedCandidate, order: Mapping[str, int]) -> tuple[int, int, str, str]:
    ref = item.candidate.ref
    return (order[ref.provider_id], item.candidate.rank, ref.provider_id, ref.native_id)


def _find(parent: list[int], index: int) -> int:
    root = index
    while parent[root] != root:
        root = parent[root]
    while parent[index] != root:
        parent[index], index = root, parent[index]
    return root


def _is_ambiguous(members: Sequence[AssessedCandidate]) -> bool:
    natives: dict[str, set[str]] = {}
    for item in members:
        natives.setdefault(item.candidate.ref.provider_id, set()).add(item.candidate.ref.native_id)
    if any(len(values) > 1 for values in natives.values()):
        return True
    for scheme in (PidScheme.INSPIRE, PidScheme.ARXIV):
        values = {
            pid.value
            for item in members
            for pid in item.candidate.identity_pids
            if pid.scheme is scheme
        }
        if len(values) > 1:
            return True
    return False


def _ref_key(item: AssessedCandidate) -> str:
    ref = item.candidate.ref
    return f"ref:{ref.provider_id}:{ref.native_id}"


def _group_key(
    members: Sequence[AssessedCandidate], identity: Sequence[PersistentIdentifier]
) -> str:
    if identity:
        return pid_text(identity[0])
    related = sorted(
        (
            pid
            for pid in members[0].candidate.related_pids
            if pid.scheme in (PidScheme.LOCAL_DOCUMENT, PidScheme.URL)
        ),
        key=pid_sort_key,
    )
    return pid_text(related[0]) if related else _ref_key(members[0])


@dataclass(slots=True)
class _Draft:
    members: list[AssessedCandidate]
    ambiguous: bool
    key: str = ""


def _finish(draft: _Draft, order: Mapping[str, int]) -> tuple[tuple[int, int, str], EvidenceGroup]:
    members = draft.members
    identity = sorted(
        {pid for item in members for pid in item.candidate.identity_pids}, key=pid_sort_key
    )
    flags: set[GroupFlag] = set()
    if draft.ambiguous:
        flags.add(GroupFlag.AMBIGUOUS_IDENTITY)
    if len({pid.value for pid in identity if pid.scheme is PidScheme.DOI}) > 1:
        flags.add(GroupFlag.MULTIPLE_DOIS)
    if len({item.candidate.access_class for item in members}) > 1:
        flags.add(GroupFlag.ACCESS_MIXED)
    best = min((item.candidate.rank, order[item.candidate.ref.provider_id]) for item in members)
    group = EvidenceGroup(
        key=draft.key,
        identity_pids=tuple(identity),
        members=tuple(members),
        flags=frozenset(flags),
        effective_access_class=most_restrictive(item.candidate.access_class for item in members),
        best_rank=best[0],
    )
    return (best[0], best[1], draft.key), group


def group_candidates(
    assessed: Sequence[AssessedCandidate], precedence_index: Mapping[str, int]
) -> tuple[EvidenceGroup, ...]:
    """Group by shared identity PIDs, split uncertain components, order deterministically.

    Groups are ordered by ``(best rank, best precedence index, key)``; no cut is applied.
    """
    nodes = sorted(assessed, key=lambda item: _node_key(item, precedence_index))
    parent = list(range(len(nodes)))
    first_holder: dict[PersistentIdentifier, int] = {}
    for index, item in enumerate(nodes):
        for pid in item.candidate.identity_pids:
            holder = first_holder.setdefault(pid, index)
            parent[_find(parent, index)] = _find(parent, holder)
    components: dict[int, list[AssessedCandidate]] = {}
    for index, item in enumerate(nodes):
        components.setdefault(_find(parent, index), []).append(item)

    drafts: list[_Draft] = []
    for members in components.values():
        if len(members) > 1 and _is_ambiguous(members):
            drafts.extend(_Draft([item], ambiguous=True) for item in members)
        else:
            drafts.append(_Draft(members, ambiguous=False))
    for draft in drafts:
        identity = sorted(
            {pid for item in draft.members for pid in item.candidate.identity_pids},
            key=pid_sort_key,
        )
        draft.key = _group_key(draft.members, identity)
    _make_keys_unique(drafts)
    finished = sorted((_finish(draft, precedence_index) for draft in drafts), key=lambda x: x[0])
    return tuple(group for _, group in finished)


def _make_keys_unique(drafts: Sequence[_Draft]) -> None:
    counts: dict[str, int] = {}
    for draft in drafts:
        counts[draft.key] = counts.get(draft.key, 0) + 1
    for draft in drafts:
        if counts[draft.key] > 1:
            draft.key = _ref_key(draft.members[0])
    seen: dict[str, int] = {}
    for draft in drafts:
        if draft.key in seen:
            seen[draft.key] += 1
            draft.key = f"{draft.key}#{seen[draft.key]}"
        else:
            seen[draft.key] = 0


# ---------------------------------------------------------------------- service


def _contract_violation() -> ProviderError:
    return ProviderError(ProviderErrorKind.MALFORMED_RESPONSE, "contract_violation")


def _valid_search(result: SearchResult, d: ProviderDescriptor, query: KnowledgeQuery) -> bool:
    if len(result.candidates) > query.limit:
        return False
    for index, candidate in enumerate(result.candidates):
        if (
            candidate.ref.provider_id != d.id
            or candidate.kind is not d.kind
            or candidate.rank != index
            or candidate.access_class.rank < d.access_class.rank
            or (d.kind in PUBLIC_NETWORK_KINDS and candidate.access_class is not AccessClass.PUBLIC)
        ):
            return False
    return True


def _valid_fetch(result: FetchResult, d: ProviderDescriptor, ref: CandidateRef) -> bool:
    candidate = result.candidate
    return (
        candidate.ref == ref
        and candidate.kind is d.kind
        and candidate.access_class.rank >= d.access_class.rank
        and (d.kind not in PUBLIC_NETWORK_KINDS or candidate.access_class is AccessClass.PUBLIC)
    )


class FederationService:
    def __init__(
        self,
        providers: Sequence[KnowledgeProvider],
        policy: FederationPolicy,
        *,
        disabled: Sequence[ProviderDescriptor] = (),
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        enabled = {provider.descriptor.id: provider for provider in providers}
        descriptors = [provider.descriptor for provider in providers] + list(disabled)
        ids = [item.id for item in descriptors]
        if len(set(ids)) != len(ids):
            raise ValueError("provider ids must be unique")
        if len(ids) > MAX_PROVIDERS:
            raise ValueError(f"at most {MAX_PROVIDERS} providers can be configured")
        if len(set(policy.precedence)) != len(policy.precedence):
            raise ValueError("precedence must list each provider at most once")
        ordered = [item for item in policy.precedence if item in ids]
        ordered += [item for item in ids if item not in ordered]
        self._enabled = enabled
        self._descriptors = {item.id: item for item in descriptors}
        self._order = tuple(ordered)
        self._index = {item: position for position, item in enumerate(ordered)}
        self._policy = policy
        self._monotonic = monotonic

    @property
    def order(self) -> tuple[str, ...]:
        return self._order

    def descriptor(self, provider_id: str) -> ProviderDescriptor | None:
        return self._descriptors.get(provider_id)

    async def _guarded(
        self,
        descriptor: ProviderDescriptor,
        call: Callable[[], Awaitable[T]],
        semaphore: asyncio.Semaphore,
    ) -> T | ProviderError:
        """Never raises an ``Exception``; cancellation and other ``BaseException`` propagate."""
        try:
            async with semaphore, asyncio.timeout(descriptor.timeout_s + self._policy.grace_s):
                return await call()
        except TimeoutError:
            return ProviderError(ProviderErrorKind.TIMEOUT, "federation_deadline")
        except Exception:
            return ProviderError(ProviderErrorKind.INTERNAL_ERROR, "unexpected_exception")

    def _skip_reason(self, descriptor: ProviderDescriptor) -> ProviderError | None:
        if descriptor.id not in self._enabled:
            return ProviderError(ProviderErrorKind.NOT_CONSULTED, "disabled")
        if descriptor.uses_network and not self._policy.live:
            return ProviderError(ProviderErrorKind.NOT_CONSULTED, "live_disabled")
        return None

    async def _run_search(
        self,
        descriptor: ProviderDescriptor,
        query: KnowledgeQuery,
        semaphore: asyncio.Semaphore,
    ) -> tuple[SearchOutcome, int]:
        provider = self._enabled[descriptor.id]
        started = self._monotonic()
        outcome: object = await self._guarded(descriptor, lambda: provider.search(query), semaphore)
        elapsed = max(0, int((self._monotonic() - started) * 1000))
        if isinstance(outcome, ProviderError):
            return outcome, elapsed
        if not isinstance(outcome, SearchResult) or not _valid_search(outcome, descriptor, query):
            return _contract_violation(), elapsed
        return outcome, elapsed

    async def search(
        self, query: KnowledgeQuery, *, only: frozenset[str] | None = None
    ) -> FederatedSearchResult:
        selected = [self._descriptors[item] for item in self._order if only is None or item in only]
        skipped: dict[str, ProviderError] = {}
        tasks: dict[str, asyncio.Task[tuple[SearchOutcome, int]]] = {}
        semaphore = asyncio.Semaphore(self._policy.max_parallel)
        async with asyncio.TaskGroup() as group:
            for descriptor in selected:
                reason = self._skip_reason(descriptor)
                if reason is None and query.access_class.rank > descriptor.max_query_access.rank:
                    reason = ProviderError(ProviderErrorKind.NOT_CONSULTED, "query_access_class")
                if reason is not None:
                    skipped[descriptor.id] = reason
                    continue
                tasks[descriptor.id] = group.create_task(
                    self._run_search(descriptor, query, semaphore)
                )

        reports: list[ProviderReport] = []
        assessed: list[AssessedCandidate] = []
        for descriptor in selected:
            if descriptor.id in skipped:
                reports.append(
                    ProviderReport(
                        descriptor.id,
                        descriptor.kind,
                        ProviderStatus.SKIPPED,
                        0,
                        0,
                        None,
                        skipped[descriptor.id],
                        0,
                    )
                )
                continue
            outcome, elapsed = tasks[descriptor.id].result()
            if isinstance(outcome, ProviderError):
                reports.append(
                    ProviderReport(
                        descriptor.id,
                        descriptor.kind,
                        ProviderStatus.FAILED,
                        0,
                        0,
                        None,
                        outcome,
                        elapsed,
                    )
                )
                continue
            status = ProviderStatus.PARTIAL if outcome.dropped_items else ProviderStatus.OK
            reports.append(
                ProviderReport(
                    descriptor.id,
                    descriptor.kind,
                    status,
                    len(outcome.candidates),
                    outcome.dropped_items,
                    outcome.total_reported,
                    None,
                    elapsed,
                )
            )
            assessed.extend(
                AssessedCandidate(candidate, suggest_authority(candidate))
                for candidate in outcome.candidates
            )
        groups = group_candidates(assessed, self._index)[: self._policy.max_groups]
        return FederatedSearchResult(query, groups, tuple(reports))

    async def fetch(self, ref: CandidateRef) -> FetchOutcome:
        descriptor = self._descriptors.get(ref.provider_id)
        if descriptor is None:
            return ProviderError(ProviderErrorKind.NOT_CONFIGURED, "unknown_provider")
        reason = self._skip_reason(descriptor)
        if reason is not None:
            return reason
        provider = self._enabled[descriptor.id]
        outcome: object = await self._guarded(
            descriptor, lambda: provider.fetch(ref), asyncio.Semaphore(1)
        )
        if isinstance(outcome, ProviderError):
            return outcome
        if not isinstance(outcome, FetchResult) or not _valid_fetch(outcome, descriptor, ref):
            return _contract_violation()
        return outcome

    async def _run_health(
        self, descriptor: ProviderDescriptor, deep: bool, semaphore: asyncio.Semaphore
    ) -> ProviderHealth:
        provider = self._enabled[descriptor.id]
        outcome: object = await self._guarded(
            descriptor, lambda: provider.health(deep=deep), semaphore
        )
        if isinstance(outcome, ProviderError):
            return ProviderHealth(descriptor.id, HealthState.UNAVAILABLE, outcome)
        if not isinstance(outcome, ProviderHealth) or outcome.provider_id != descriptor.id:
            return ProviderHealth(descriptor.id, HealthState.UNAVAILABLE, _contract_violation())
        return outcome

    async def health(self, *, deep: bool = False) -> tuple[ProviderHealth, ...]:
        results: dict[str, ProviderHealth] = {}
        tasks: dict[str, asyncio.Task[ProviderHealth]] = {}
        semaphore = asyncio.Semaphore(self._policy.max_parallel)
        async with asyncio.TaskGroup() as group:
            for provider_id in self._order:
                descriptor = self._descriptors[provider_id]
                reason = self._skip_reason(descriptor)
                if reason is not None:
                    results[provider_id] = ProviderHealth(
                        provider_id, HealthState.NOT_CONSULTED, reason
                    )
                else:
                    tasks[provider_id] = group.create_task(
                        self._run_health(descriptor, deep, semaphore)
                    )
        return tuple(
            results[item] if item in results else tasks[item].result() for item in self._order
        )
