"""Shared mechanics of the public HTTP adapters (INSPIRE, arXiv, HEPData).

Every helper here is deterministic and network-free except ``gated_get``, which sends
exactly one GET through the injected client factory after the provider's rate gate. Base
URLs and request parameters are built by the adapters from fixed constants and validated
ids; nothing in a response ever causes another request.
"""

import asyncio
import hashlib
import re
from collections.abc import Awaitable, Callable, Iterable, Sequence
from datetime import datetime
from typing import Final, TypeVar

from asca.application.knowledge.models import (
    PIDS_MAX,
    CandidatePid,
    CandidateRef,
    DocumentKind,
    FetchedDocument,
    HealthState,
    KnowledgeQuery,
    LicenseInfo,
    LicenseScope,
    PidRole,
    ProviderDescriptor,
    ProviderError,
    ProviderErrorKind,
    ProviderHealth,
    ProviderKind,
)
from asca.application.knowledge.pids import pid_sort_key
from asca.application.knowledge.text import clean_block, clean_line
from asca.domain.provenance import AccessClass, sha256_text
from asca.infrastructure.knowledge.http import (
    ClientFactory,
    ClientSpec,
    MinIntervalGate,
    RawResponse,
    bounded_get,
)
from asca.infrastructure.knowledge.settings import NetworkSettings

PLAIN_TEXT: Final = "text/plain; charset=utf-8"
CC0_METADATA: Final = LicenseInfo("CC0-1.0", None, LicenseScope.METADATA)
ABSTRACT_TEXT_MAX: Final = 1_000_000
_T = TypeVar("_T")


def public_descriptor(
    kind: ProviderKind, label: str, adapter_version: str, *, timeout_s: float, supports_fetch: bool
) -> ProviderDescriptor:
    """The descriptor of a public network provider: public data, public queries only."""
    return ProviderDescriptor(
        id=kind.value,
        kind=kind,
        label=label,
        adapter_version=adapter_version,
        access_class=AccessClass.PUBLIC,
        access_conditions=None,
        max_query_access=AccessClass.PUBLIC,
        uses_network=True,
        supports_fetch=supports_fetch,
        timeout_s=timeout_s,
    )


def error(kind: ProviderErrorKind, code: str) -> ProviderError:
    return ProviderError(kind, code)


def refuse_query(query: KnowledgeQuery, descriptor: ProviderDescriptor) -> ProviderError | None:
    """Defence in depth: a query more sensitive than the provider may receive is refused."""
    if query.access_class.rank > descriptor.max_query_access.rank:
        return error(ProviderErrorKind.NOT_CONSULTED, "query_access_class")
    return None


def refuse_ref(
    ref: CandidateRef, descriptor: ProviderDescriptor, pattern: re.Pattern[str]
) -> ProviderError | None:
    """A ref from another provider, or a native id outside the adapter's grammar."""
    if ref.provider_id != descriptor.id or pattern.fullmatch(ref.native_id) is None:
        return error(ProviderErrorKind.UNSUPPORTED, "invalid_native_id")
    return None


async def within_timeout(
    timeout_s: float, operation: Callable[[], Awaitable[_T]], on_timeout: _T
) -> _T:
    """Run ``operation`` under the adapter's own timeout (contract rule 2)."""
    try:
        async with asyncio.timeout(timeout_s):
            return await operation()
    except TimeoutError:
        return on_timeout


def timed_out() -> ProviderError:
    return error(ProviderErrorKind.TIMEOUT, "provider_timeout")


async def gated_get(
    *,
    gate: MinIntervalGate,
    deadline: float,
    monotonic: Callable[[], float],
    client_factory: ClientFactory,
    spec: ClientSpec,
    network: NetworkSettings,
    url: str,
    params: Sequence[tuple[str, str]],
) -> RawResponse | ProviderError:
    """Wait for the rate gate inside the remaining budget, then send one bounded GET."""
    refused = await gate.wait(deadline - monotonic())
    if refused is not None:
        return refused
    async with client_factory(spec, network) as client:
        return await bounded_get(client, url, params)


def has_content_type(raw: RawResponse, prefix: str) -> bool:
    return raw.content_type.strip().lower().startswith(prefix)


def wrong_content_type() -> ProviderError:
    return error(ProviderErrorKind.MALFORMED_RESPONSE, "unexpected_content_type")


def unexpected_payload() -> ProviderError:
    return error(ProviderErrorKind.MALFORMED_RESPONSE, "unexpected_payload")


def health_from(provider_id: str, outcome: ProviderError | None) -> ProviderHealth:
    """AVAILABLE without an error; AUTH_REQUIRED for 401/403; otherwise UNAVAILABLE."""
    if outcome is None:
        return ProviderHealth(provider_id, HealthState.AVAILABLE, None)
    if outcome.kind is ProviderErrorKind.AUTH_REQUIRED:
        return ProviderHealth(provider_id, HealthState.AUTH_REQUIRED, outcome)
    return ProviderHealth(provider_id, HealthState.UNAVAILABLE, outcome)


def line(raw: object, max_len: int) -> str | None:
    """A cleaned single line, or ``None`` for a non-string or blank value."""
    if not isinstance(raw, str):
        return None
    cleaned = clean_line(raw, max_len)
    return None if cleaned is None else cleaned[0]


def lines(values: Iterable[object], max_len: int, max_items: int) -> tuple[str, ...]:
    """Cleaned, de-duplicated lines in order, at most ``max_items``."""
    seen: dict[str, None] = {}
    for value in values:
        cleaned = line(value, max_len)
        if cleaned is not None:
            seen.setdefault(cleaned, None)
    return tuple(seen)[:max_items]


def block(raw: object, max_len: int) -> str | None:
    return clean_block(raw, max_len) if isinstance(raw, str) else None


def assemble_pids(items: Iterable[CandidatePid]) -> tuple[CandidatePid, ...]:
    """Unique by (scheme, value) (identity wins), at most 16 (identity first), sorted."""
    chosen: dict[tuple[int, str], CandidatePid] = {}
    for item in items:
        key = pid_sort_key(item.pid)
        known = chosen.get(key)
        if known is None or (known.role is PidRole.RELATED and item.role is PidRole.IDENTITY):
            chosen[key] = item
    ordered = sorted(
        chosen.items(), key=lambda pair: (pair[1].role is not PidRole.IDENTITY, pair[0])
    )
    kept = sorted(ordered[:PIDS_MAX], key=lambda pair: pair[0])
    return tuple(item for _, item in kept)


def text_document(
    *,
    ref: CandidateRef,
    title: str,
    abstract: str | None,
    raw: RawResponse,
    retrieved_at: datetime,
    licenses: tuple[LicenseInfo, ...],
) -> FetchedDocument:
    """``asca-abstract-text/1``: ``title\\n\\nabstract\\n``, or ``title\\n`` without one."""
    if abstract is None:
        kind, text = DocumentKind.METADATA_TEXT, f"{title}\n"
    else:
        kind, text = DocumentKind.ABSTRACT_TEXT, f"{title}\n\n{abstract}\n"
    return FetchedDocument(
        ref=ref,
        kind=kind,
        media_type=PLAIN_TEXT,
        text=text,
        text_sha256=sha256_text(text),
        raw_sha256=sha256_bytes(raw.body),
        retrieved_at=retrieved_at,
        source_url=raw.url,
        access_class=AccessClass.PUBLIC,
        access_conditions=None,
        licenses=licenses,
        redactions=0,
    )


def sha256_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()
