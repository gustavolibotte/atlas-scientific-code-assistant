"""Knowledge port models: enums, value types and outcomes.

Every value type validates itself in ``__post_init__`` and raises ``ValueError`` with a
fixed message naming the field; messages never echo provider text. No type here can carry
headers, tokens, cookies, credentialed URLs or exception text.
"""

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from enum import StrEnum
from itertools import pairwise
from typing import Final
from urllib.parse import urlsplit

from asca.application.knowledge.pids import IDENTITY_SCHEMES, pid_sort_key
from asca.application.knowledge.pids import PidRole as PidRole
from asca.application.knowledge.text import is_block, is_line
from asca.domain.provenance import (
    TITLE_MAX,
    AccessClass,
    PersistentIdentifier,
    PidScheme,
    SourceAuthority,
    sha256_text,
)
from asca.domain.provenance.sources import VERSION_LABEL_MAX

QUERY_TEXT_MAX: Final = 300
QUERY_LIMIT_MAX: Final = 25
NATIVE_ID_MAX: Final = 200
AUTHORS_MAX: Final = 5
AUTHOR_MAX: Final = 200
COLLABORATIONS_MAX: Final = 5
DOCUMENT_TYPES_MAX: Final = 5
DOCUMENT_TYPE_MAX: Final = 50
JOURNAL_REF_MAX: Final = 300
SNIPPET_MAX: Final = 500
LANDING_URL_MAX: Final = 500
PIDS_MAX: Final = 16
LICENSES_MAX: Final = 4
RESULTS_MAX: Final = 25
DOCUMENT_TEXT_MAX_BYTES: Final = 4_194_304
TOOL_NAMES_MAX: Final = 200
CONDITIONS_MAX: Final = 2000
LABEL_MAX: Final = 80
LICENSE_ID_MAX: Final = 64
PROVIDER_ID_RE: Final = r"[a-z][a-z0-9-]{0,31}(:[a-z][a-z0-9-]{0,31})?"
ADAPTER_VERSION_RE: Final = r"[a-z]+/[1-9][0-9]{0,2}"
ERROR_CODE_RE: Final = r"[a-z0-9_]{1,40}"
TOOL_NAME_RE: Final = r"[A-Za-z0-9_.-]{1,64}"
MEDIA_TYPES: Final = frozenset({"text/plain; charset=utf-8", "text/markdown; charset=utf-8"})

_PROVIDER_ID = re.compile(PROVIDER_ID_RE)
_ADAPTER_VERSION = re.compile(ADAPTER_VERSION_RE)
_ERROR_CODE = re.compile(ERROR_CODE_RE)
_TOOL_NAME = re.compile(TOOL_NAME_RE)
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PARTIAL_DATE = re.compile(r"(\d{4})(?:-(\d{2})(?:-(\d{2}))?)?")


# ---------------------------------------------------------------------- validators


def _fail(field: str, rule: str) -> ValueError:
    return ValueError(f"{field} {rule}")


def _require_line(field: str, value: object, max_len: int) -> str:
    if not isinstance(value, str) or not is_line(value) or len(value) > max_len:
        raise _fail(field, f"must be a clean single line of at most {max_len} characters")
    return value


def _optional_line(field: str, value: object, max_len: int) -> str | None:
    return None if value is None else _require_line(field, value, max_len)


def _optional_block(field: str, value: object, max_len: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not is_block(value) or len(value) > max_len:
        raise _fail(field, f"must be clean text of at most {max_len} characters")
    return value


def _require_int(field: str, value: object, minimum: int, maximum: int | None = None) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or (maximum is not None and value > maximum)
    ):
        raise _fail(field, "is out of range")
    return value


def _optional_int(field: str, value: object, minimum: int, maximum: int | None = None) -> None:
    if value is not None:
        _require_int(field, value, minimum, maximum)


def _require_bool(field: str, value: object) -> None:
    if not isinstance(value, bool):
        raise _fail(field, "must be a bool")


def _require_type(field: str, value: object, kind: type) -> None:
    if not isinstance(value, kind):
        raise _fail(field, f"must be a {kind.__name__}")


def _require_tuple(field: str, value: object, kind: type, max_len: int) -> None:
    if (
        not isinstance(value, tuple)
        or len(value) > max_len
        or not all(isinstance(item, kind) for item in value)
    ):
        raise _fail(field, f"must be a tuple of at most {max_len} {kind.__name__}")


def _require_timeout(field: str, value: object) -> None:
    if (
        not isinstance(value, int | float)
        or isinstance(value, bool)
        or not 1.0 <= float(value) <= 30.0
    ):
        raise _fail(field, "must be between 1.0 and 30.0 seconds")


def _require_utc(field: str, value: object) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise _fail(field, "must be an aware UTC datetime")


def require_provider_id(field: str, value: object) -> str:
    if not isinstance(value, str) or _PROVIDER_ID.fullmatch(value) is None:
        raise _fail(field, "is not a valid provider id")
    return value


def _access_conditions(field: str, access: AccessClass, conditions: object) -> None:
    _require_type(f"{field}.access_class", access, AccessClass)
    _optional_block(f"{field}.access_conditions", conditions, CONDITIONS_MAX)
    if (access is AccessClass.PUBLIC) != (conditions is None):
        raise _fail(f"{field}.access_conditions", "is required exactly when access is not public")


def is_https_url(value: object, max_len: int) -> bool:
    """An https URL with a host, no userinfo, no whitespace or controls, bounded length."""
    if not isinstance(value, str) or not 1 <= len(value) <= max_len:
        return False
    if any(char.isspace() or not char.isprintable() for char in value):
        return False
    try:
        parts = urlsplit(value)
        _ = parts.port
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and bool(parts.hostname)
        and parts.username is None
        and parts.password is None
    )


# ---------------------------------------------------------------------- enums


class ProviderKind(StrEnum):
    INSPIRE = "inspire"
    ARXIV = "arxiv"
    HEPDATA = "hepdata"
    LOCAL = "local"
    MCP = "mcp"


PUBLIC_NETWORK_KINDS: Final = frozenset(
    {ProviderKind.INSPIRE, ProviderKind.ARXIV, ProviderKind.HEPDATA}
)


class PidOrigin(StrEnum):
    NATIVE = "native"
    """The provider's own id (INSPIRE recid, arXiv id, HEPData concept DOI)."""
    CURATED_LINK = "curated_link"
    """Recorded by a curated database or by the local curator."""
    PROVIDER_ASSERTED = "provider_asserted"
    """An uncurated claim (arXiv's author-supplied DOI, MCP metadata)."""


class VersionKind(StrEnum):
    ARXIV_VERSION = "arxiv_version"
    JOURNAL_PUBLICATION = "journal_publication"
    REPORT_NUMBER = "report_number"
    DATASET_VERSION = "dataset_version"
    DECLARED = "declared"
    RECORD_SNAPSHOT = "record_snapshot"


class ContentAvailability(StrEnum):
    METADATA_ONLY = "metadata_only"
    ABSTRACT = "abstract"
    FULL_TEXT = "full_text"


class LicenseScope(StrEnum):
    METADATA = "metadata"
    CONTENT = "content"


class DocumentKind(StrEnum):
    ABSTRACT_TEXT = "abstract_text"
    METADATA_TEXT = "metadata_text"
    FULL_TEXT = "full_text"
    TOOL_TEXT = "tool_text"
    GENERATED_TEXT = "generated_text"


class ProviderErrorKind(StrEnum):
    NOT_CONSULTED = "not_consulted"
    NOT_CONFIGURED = "not_configured"
    TIMEOUT = "timeout"
    DNS_FAILED = "dns_failed"
    CONNECT_FAILED = "connect_failed"
    TLS_FAILED = "tls_failed"
    HTTP_STATUS = "http_status"
    RATE_LIMITED = "rate_limited"
    BLOCKED = "blocked"
    AUTH_REQUIRED = "auth_required"
    UNEXPECTED_REDIRECT = "unexpected_redirect"
    RESPONSE_TOO_LARGE = "response_too_large"
    UNSUPPORTED_ENCODING = "unsupported_encoding"
    MALFORMED_RESPONSE = "malformed_response"
    NOT_FOUND = "not_found"
    UNSUPPORTED = "unsupported"
    TOOL_ERROR = "tool_error"
    PROTOCOL_ERROR = "protocol_error"
    PROCESS_FAILED = "process_failed"
    INTERNAL_ERROR = "internal_error"


class HealthState(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    AUTH_REQUIRED = "auth_required"
    MISCONFIGURED = "misconfigured"
    NOT_PROBED = "not_probed"
    NOT_CONSULTED = "not_consulted"


# ---------------------------------------------------------------------- value types


@dataclass(frozen=True, slots=True)
class KnowledgeQuery:
    text: str
    limit: int = 5
    access_class: AccessClass = AccessClass.PUBLIC
    """How sensitive the query text is."""

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text.strip():
            raise ValueError("Search query cannot be blank")
        if self.text != self.text.strip():
            raise ValueError("Search query must not have surrounding whitespace")
        _require_line("query.text", self.text, QUERY_TEXT_MAX)
        if not isinstance(self.limit, int) or isinstance(self.limit, bool):
            raise ValueError("Search limit must be an integer")
        if not 1 <= self.limit <= QUERY_LIMIT_MAX:
            raise ValueError(f"Search limit must be between 1 and {QUERY_LIMIT_MAX}")
        _require_type("query.access_class", self.access_class, AccessClass)


@dataclass(frozen=True, slots=True)
class ProviderDescriptor:
    id: str
    kind: ProviderKind
    label: str
    adapter_version: str
    access_class: AccessClass
    access_conditions: str | None
    max_query_access: AccessClass
    """The most sensitive query this provider may receive."""
    uses_network: bool
    supports_fetch: bool
    timeout_s: float

    def __post_init__(self) -> None:
        require_provider_id("descriptor.id", self.id)
        _require_type("descriptor.kind", self.kind, ProviderKind)
        _require_line("descriptor.label", self.label, LABEL_MAX)
        if (
            not isinstance(self.adapter_version, str)
            or _ADAPTER_VERSION.fullmatch(self.adapter_version) is None
        ):
            raise _fail("descriptor.adapter_version", "is not a valid adapter version")
        _access_conditions("descriptor", self.access_class, self.access_conditions)
        _require_type("descriptor.max_query_access", self.max_query_access, AccessClass)
        _require_bool("descriptor.uses_network", self.uses_network)
        _require_bool("descriptor.supports_fetch", self.supports_fetch)
        _require_timeout("descriptor.timeout_s", self.timeout_s)
        if self.kind in PUBLIC_NETWORK_KINDS:
            if (
                self.access_class is not AccessClass.PUBLIC
                or self.max_query_access is not AccessClass.PUBLIC
                or not self.uses_network
                or self.id != self.kind.value
            ):
                raise _fail("descriptor", "of a public network provider is inconsistent")
        elif self.kind is ProviderKind.LOCAL:
            if (
                self.uses_network
                or self.max_query_access is not AccessClass.RESTRICTED
                or self.id != "local"
            ):
                raise _fail("descriptor", "of the local library is inconsistent")
        elif not self.uses_network or not self.id.startswith("mcp:"):
            raise _fail("descriptor", "of an MCP provider is inconsistent")


@dataclass(frozen=True, slots=True)
class CandidateRef:
    provider_id: str
    native_id: str

    def __post_init__(self) -> None:
        require_provider_id("ref.provider_id", self.provider_id)
        _require_line("ref.native_id", self.native_id, NATIVE_ID_MAX)
        if any(char.isspace() for char in self.native_id):
            raise _fail("ref.native_id", "must not contain whitespace")


@dataclass(frozen=True, slots=True)
class CandidatePid:
    pid: PersistentIdentifier
    role: PidRole
    origin: PidOrigin

    def __post_init__(self) -> None:
        _require_type("pid.pid", self.pid, PersistentIdentifier)
        _require_type("pid.role", self.role, PidRole)
        _require_type("pid.origin", self.origin, PidOrigin)
        if self.role is PidRole.IDENTITY and self.pid.scheme not in IDENTITY_SCHEMES:
            raise _fail("pid.role", "identity requires an identity scheme")


@dataclass(frozen=True, slots=True)
class PartialDate:
    year: int
    month: int | None = None
    day: int | None = None

    def __post_init__(self) -> None:
        _require_int("date.year", self.year, 1000, 2100)
        _optional_int("date.month", self.month, 1, 12)
        _optional_int("date.day", self.day, 1, 31)
        if self.day is not None:
            if self.month is None:
                raise _fail("date.day", "requires a month")
            try:
                date(self.year, self.month, self.day)
            except ValueError:
                raise _fail("date", "is not a calendar date") from None

    def as_date(self) -> date | None:
        if self.month is None or self.day is None:
            return None
        return date(self.year, self.month, self.day)

    def iso(self) -> str:
        text = f"{self.year:04d}"
        if self.month is not None:
            text += f"-{self.month:02d}"
        if self.day is not None:
            text += f"-{self.day:02d}"
        return text

    @classmethod
    def parse(cls, raw: str) -> "PartialDate | None":
        """Accept ``YYYY``, ``YYYY-MM``, ``YYYY-MM-DD`` or an ISO datetime (date part)."""
        if not isinstance(raw, str):
            return None
        value = raw.strip()
        match = _PARTIAL_DATE.fullmatch(value)
        try:
            if match is not None:
                year, month, day = match.groups()
                return cls(
                    int(year),
                    None if month is None else int(month),
                    None if day is None else int(day),
                )
            if len(value) > 10 and value[10] in "T ":
                moment = datetime.fromisoformat(value)
                return cls(moment.year, moment.month, moment.day)
        except ValueError:
            return None
        return None


_VERSION_LABELS: Final = {
    VersionKind.ARXIV_VERSION: re.compile(
        r"arXiv:(\d{4}\.\d{4,5}|[a-z-]+(\.[A-Z]{2})?/\d{7})v[1-9]\d{0,3}"
    ),
    VersionKind.JOURNAL_PUBLICATION: re.compile(r"doi:10\.\d{4,9}/\S+"),
    VersionKind.REPORT_NUMBER: re.compile(r"report:[A-Z][A-Z0-9]*(-[A-Z0-9]+){2,6}"),
    VersionKind.DATASET_VERSION: re.compile(r"doi:10\.17182/hepdata\.\d{1,9}\.v[1-9]\d{0,3}"),
    VersionKind.DECLARED: re.compile(r"declared:\S.{0,90}"),
    VersionKind.RECORD_SNAPSHOT: re.compile(r"(inspire:[1-9]\d{0,9}|retrieved)@\d{4}-\d{2}-\d{2}"),
}


@dataclass(frozen=True, slots=True)
class CandidateVersion:
    kind: VersionKind
    label: str

    def __post_init__(self) -> None:
        _require_type("version.kind", self.kind, VersionKind)
        _require_line("version.label", self.label, VERSION_LABEL_MAX)
        if _VERSION_LABELS[self.kind].fullmatch(self.label) is None:
            raise _fail("version.label", f"does not match the {self.kind.value} grammar")


KNOWN_LICENSES: Final[dict[str, str]] = {
    "creativecommons.org/publicdomain/zero/1.0/": "CC0-1.0",
    "creativecommons.org/licenses/by/3.0/": "CC-BY-3.0",
    "creativecommons.org/licenses/by/4.0/": "CC-BY-4.0",
    "creativecommons.org/licenses/by-sa/4.0/": "CC-BY-SA-4.0",
    "creativecommons.org/licenses/by-nc-sa/4.0/": "CC-BY-NC-SA-4.0",
    "creativecommons.org/licenses/by-nc-nd/4.0/": "CC-BY-NC-ND-4.0",
    "arxiv.org/licenses/nonexclusive-distrib/1.0/": "arXiv-nonexclusive-distrib-1.0",
}


def _is_http_url(value: object) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= LANDING_URL_MAX:
        return False
    if any(char.isspace() or not char.isprintable() for char in value):
        return False
    parts = urlsplit(value)
    return parts.scheme in ("http", "https") and bool(parts.netloc) and "@" not in parts.netloc


@dataclass(frozen=True, slots=True)
class LicenseInfo:
    identifier: str | None
    url: str | None
    scope: LicenseScope

    def __post_init__(self) -> None:
        _optional_line("license.identifier", self.identifier, LICENSE_ID_MAX)
        if self.url is not None and not _is_http_url(self.url):
            raise _fail("license.url", "must be an http(s) URL of at most 500 characters")
        _require_type("license.scope", self.scope, LicenseScope)
        if self.identifier is None and self.url is None:
            raise _fail("license", "needs an identifier or a URL")


def license_from_url(url: str, scope: LicenseScope) -> LicenseInfo | None:
    """Map a licence URL to a known identifier; ``None`` when the URL is invalid."""
    if not _is_http_url(url):
        return None
    normalized = url.lower().removeprefix("https://").removeprefix("http://")
    if not normalized.endswith("/"):
        normalized += "/"
    return LicenseInfo(KNOWN_LICENSES.get(normalized), url, scope)


@dataclass(frozen=True, slots=True)
class PublicationFacts:
    """What the provider asserts; not ASCA authority."""

    refereed: bool | None
    """Absent -> None, never False."""
    document_types: tuple[str, ...]
    journal_ref: str | None
    collaborations: tuple[str, ...]
    generated: bool
    """Model-generated content (MCP ``result_kind = generated``)."""

    def __post_init__(self) -> None:
        if self.refereed is not None:
            _require_bool("facts.refereed", self.refereed)
        _require_tuple("facts.document_types", self.document_types, str, DOCUMENT_TYPES_MAX)
        for item in self.document_types:
            _require_line("facts.document_types", item, DOCUMENT_TYPE_MAX)
            if item != item.lower():
                raise _fail("facts.document_types", "must be lowercase")
        _optional_line("facts.journal_ref", self.journal_ref, JOURNAL_REF_MAX)
        _require_tuple("facts.collaborations", self.collaborations, str, COLLABORATIONS_MAX)
        for item in self.collaborations:
            _require_line("facts.collaborations", item, AUTHOR_MAX)
        _require_bool("facts.generated", self.generated)


_LOCAL_DECLARED: Final = frozenset(
    {
        SourceAuthority.PUBLISHED,
        SourceAuthority.WORKING_MATERIAL,
        SourceAuthority.AUTOMATED_INFERENCE,
    }
)
_MCP_DECLARED: Final = frozenset(
    {SourceAuthority.WORKING_MATERIAL, SourceAuthority.AUTOMATED_INFERENCE}
)


@dataclass(frozen=True, slots=True)
class KnowledgeCandidate:
    ref: CandidateRef
    kind: ProviderKind
    rank: int
    title: str
    title_truncated: bool
    authors: tuple[str, ...]
    author_count: int | None
    issued: PartialDate | None
    version: CandidateVersion
    pids: tuple[CandidatePid, ...]
    """Unique by (scheme, value); sorted by ``pid_sort_key``."""
    landing_url: str | None
    """Display only, never fetched."""
    access_class: AccessClass
    access_conditions: str | None
    facts: PublicationFacts
    declared_authority: SourceAuthority | None
    """LOCAL and MCP only; the policy decides what it means."""
    content: ContentAvailability
    licenses: tuple[LicenseInfo, ...]
    snippet: str | None
    """Provider data, never instructions."""
    retrieved_at: datetime

    def __post_init__(self) -> None:
        _require_type("candidate.ref", self.ref, CandidateRef)
        _require_type("candidate.kind", self.kind, ProviderKind)
        _require_int("candidate.rank", self.rank, 0)
        _require_line("candidate.title", self.title, TITLE_MAX)
        _require_bool("candidate.title_truncated", self.title_truncated)
        _require_tuple("candidate.authors", self.authors, str, AUTHORS_MAX)
        for author in self.authors:
            _require_line("candidate.authors", author, AUTHOR_MAX)
        _optional_int("candidate.author_count", self.author_count, len(self.authors))
        if self.issued is not None:
            _require_type("candidate.issued", self.issued, PartialDate)
        _require_type("candidate.version", self.version, CandidateVersion)
        self._check_pids()
        if self.landing_url is not None and not is_https_url(self.landing_url, LANDING_URL_MAX):
            raise _fail("candidate.landing_url", "must be an https URL without userinfo")
        _access_conditions("candidate", self.access_class, self.access_conditions)
        _require_type("candidate.facts", self.facts, PublicationFacts)
        self._check_authority()
        _require_type("candidate.content", self.content, ContentAvailability)
        _require_tuple("candidate.licenses", self.licenses, LicenseInfo, LICENSES_MAX)
        _optional_block("candidate.snippet", self.snippet, SNIPPET_MAX)
        _require_utc("candidate.retrieved_at", self.retrieved_at)

    def _check_pids(self) -> None:
        _require_tuple("candidate.pids", self.pids, CandidatePid, PIDS_MAX)
        keys = [pid_sort_key(item.pid) for item in self.pids]
        if any(left >= right for left, right in pairwise(keys)):
            raise _fail("candidate.pids", "must be unique and sorted by pid_sort_key")
        for scheme in (PidScheme.INSPIRE, PidScheme.ARXIV):
            if sum(1 for pid in self.identity_pids if pid.scheme is scheme) > 1:
                raise _fail("candidate.pids", f"hold at most one identity {scheme.value} pid")
        if self.kind is ProviderKind.MCP and self.identity_pids:
            raise _fail("candidate.pids", "of an MCP candidate are never identity pids")

    def _check_authority(self) -> None:
        if self.facts.generated and self.kind is not ProviderKind.MCP:
            raise _fail("candidate.facts.generated", "is only possible for MCP candidates")
        declared = self.declared_authority
        if self.kind is ProviderKind.LOCAL:
            allowed: frozenset[SourceAuthority] = _LOCAL_DECLARED
        elif self.kind is ProviderKind.MCP:
            allowed = _MCP_DECLARED
        else:
            if declared is not None:
                raise _fail("candidate.declared_authority", "is only set for LOCAL and MCP")
            return
        if declared not in allowed:
            raise _fail("candidate.declared_authority", f"is not allowed for {self.kind.value}")

    @property
    def identity_pids(self) -> tuple[PersistentIdentifier, ...]:
        return tuple(item.pid for item in self.pids if item.role is PidRole.IDENTITY)

    @property
    def related_pids(self) -> tuple[PersistentIdentifier, ...]:
        return tuple(item.pid for item in self.pids if item.role is PidRole.RELATED)


@dataclass(frozen=True, slots=True)
class FetchedDocument:
    ref: CandidateRef
    kind: DocumentKind
    media_type: str
    text: str
    """The exact canonical text used for quoting."""
    text_sha256: str
    raw_sha256: str | None
    """sha256 of the raw response body (audit); None for local and MCP."""
    retrieved_at: datetime
    source_url: str | None
    """https request URL built from a fixed base and validated ids; None for local/MCP."""
    access_class: AccessClass
    access_conditions: str | None
    licenses: tuple[LicenseInfo, ...]
    redactions: int
    """Count of secret echoes replaced (MCP)."""

    def __post_init__(self) -> None:
        _require_type("document.ref", self.ref, CandidateRef)
        _require_type("document.kind", self.kind, DocumentKind)
        if self.media_type not in MEDIA_TYPES:
            raise _fail("document.media_type", "is not supported")
        if (
            not isinstance(self.text, str)
            or not self.text
            or "\x00" in self.text
            or len(self.text.encode("utf-8", errors="replace")) > DOCUMENT_TEXT_MAX_BYTES
        ):
            raise _fail("document.text", "must be 1 byte to 4 MiB of UTF-8 text without NUL")
        try:
            digest = sha256_text(self.text)
        except UnicodeEncodeError:
            raise _fail("document.text", "must be valid UTF-8 text") from None
        if self.text_sha256 != digest:
            raise _fail("document.text_sha256", "does not match the text")
        if self.raw_sha256 is not None and (
            not isinstance(self.raw_sha256, str) or _SHA256.fullmatch(self.raw_sha256) is None
        ):
            raise _fail("document.raw_sha256", "must be 64 lowercase hex")
        _require_utc("document.retrieved_at", self.retrieved_at)
        if self.source_url is not None and not is_https_url(self.source_url, 2000):
            raise _fail("document.source_url", "must be an https URL")
        _access_conditions("document", self.access_class, self.access_conditions)
        _require_tuple("document.licenses", self.licenses, LicenseInfo, LICENSES_MAX)
        _require_int("document.redactions", self.redactions, 0)


@dataclass(frozen=True, slots=True)
class FetchResult:
    candidate: KnowledgeCandidate
    document: FetchedDocument

    def __post_init__(self) -> None:
        _require_type("fetch.candidate", self.candidate, KnowledgeCandidate)
        _require_type("fetch.document", self.document, FetchedDocument)
        if self.document.ref != self.candidate.ref:
            raise _fail("fetch.document.ref", "must equal the candidate ref")
        if self.document.access_class is not self.candidate.access_class:
            raise _fail("fetch.document.access_class", "must equal the candidate access class")


@dataclass(frozen=True, slots=True)
class SearchResult:
    candidates: tuple[KnowledgeCandidate, ...]
    """Ranks are exactly 0..n-1 in order; one provider id."""
    total_reported: int | None
    dropped_items: int
    """Invalid items skipped by the adapter."""

    def __post_init__(self) -> None:
        _require_tuple("search.candidates", self.candidates, KnowledgeCandidate, RESULTS_MAX)
        if [item.rank for item in self.candidates] != list(range(len(self.candidates))):
            raise _fail("search.candidates", "ranks must be 0..n-1 in order")
        if len({item.ref.provider_id for item in self.candidates}) > 1:
            raise _fail("search.candidates", "must come from one provider")
        _optional_int("search.total_reported", self.total_reported, 0)
        _require_int("search.dropped_items", self.dropped_items, 0)


@dataclass(frozen=True, slots=True)
class ProviderError:
    kind: ProviderErrorKind
    code: str
    http_status: int | None = None
    retry_after_s: int | None = None

    def __post_init__(self) -> None:
        _require_type("error.kind", self.kind, ProviderErrorKind)
        if not isinstance(self.code, str) or _ERROR_CODE.fullmatch(self.code) is None:
            raise _fail("error.code", "is not a valid error code")
        _optional_int("error.http_status", self.http_status, 100, 599)
        _optional_int("error.retry_after_s", self.retry_after_s, 0, 3600)


SearchOutcome = SearchResult | ProviderError
FetchOutcome = FetchResult | ProviderError

_HEALTHY: Final = frozenset({HealthState.AVAILABLE, HealthState.NOT_PROBED})


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    provider_id: str
    state: HealthState
    error: ProviderError | None
    """None exactly when the state is AVAILABLE or NOT_PROBED."""
    tool_names: tuple[str, ...] = ()
    """MCP only; names only."""

    def __post_init__(self) -> None:
        require_provider_id("health.provider_id", self.provider_id)
        _require_type("health.state", self.state, HealthState)
        if self.error is not None:
            _require_type("health.error", self.error, ProviderError)
        if (self.error is None) != (self.state in _HEALTHY):
            raise _fail("health.error", "is required exactly when the state is not healthy")
        _require_tuple("health.tool_names", self.tool_names, str, TOOL_NAMES_MAX)
        if any(_TOOL_NAME.fullmatch(name) is None for name in self.tool_names):
            raise _fail("health.tool_names", "hold an invalid tool name")
