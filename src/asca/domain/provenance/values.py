"""Shared value validators and value objects of the provenance domain."""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum, StrEnum
from typing import TypeGuard, TypeVar

from asca.domain.provenance.errors import ProvenanceInvariantError

TITLE_MAX = 300
SHORT_MAX = 200
STATEMENT_MAX = 2000
QUOTE_MAX = 5000
LONG_MAX = 10000
PID_MAX = 2000
PATH_MAX = 500

_SHA256_RE = re.compile(r"[0-9a-f]{64}")

E = TypeVar("E", bound=Enum)


def require_text(field: str, value: object, *, max_len: int, multiline: bool = False) -> str:
    if not isinstance(value, str):
        raise ProvenanceInvariantError("R.text.type", f"{field} must be a string")
    if value.strip() == "":
        raise ProvenanceInvariantError("R.text.blank", f"{field} must not be blank")
    if "\x00" in value:
        raise ProvenanceInvariantError("R.text.nul", f"{field} must not contain NUL")
    if not multiline and ("\r" in value or "\n" in value):
        raise ProvenanceInvariantError("R.text.newline", f"{field} must be a single line")
    if len(value) > max_len:
        raise ProvenanceInvariantError(
            "R.text.length", f"{field} must be at most {max_len} characters"
        )
    return value


def optional_text(
    field: str, value: object, *, max_len: int, multiline: bool = False
) -> str | None:
    if value is None:
        return None
    return require_text(field, value, max_len=max_len, multiline=multiline)


def require_utc(field: str, value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ProvenanceInvariantError("R.time.utc", f"{field} must be an aware UTC datetime")
    return value


def optional_utc(field: str, value: object) -> datetime | None:
    return None if value is None else require_utc(field, value)


def require_sha256(field: str, value: object) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ProvenanceInvariantError("R.hash.format", f"{field} must be 64 lowercase hex")
    return value


def optional_sha256(field: str, value: object) -> str | None:
    return None if value is None else require_sha256(field, value)


def is_relative_path(value: object) -> TypeGuard[str]:
    if not isinstance(value, str) or not 1 <= len(value) <= PATH_MAX:
        return False
    if "\x00" in value or "\\" in value or value.startswith("/"):
        return False
    segments = value.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        return False
    return ":" not in segments[0]


def require_relative_path(field: str, value: object) -> str:
    if not is_relative_path(value):
        raise ProvenanceInvariantError(
            "R.path.relative", f"{field} must be a normalized workspace-relative path"
        )
    return value


def require_int(field: str, value: object, *, minimum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ProvenanceInvariantError("R.int.range", f"{field} must be an integer >= {minimum}")
    return value


def require_bool(field: str, value: object) -> bool:
    if not isinstance(value, bool):
        raise ProvenanceInvariantError("R.bool.type", f"{field} must be a bool")
    return value


def require_enum(enum_type: type[E], field: str, value: object) -> E:
    if not isinstance(value, enum_type):
        raise ProvenanceInvariantError(
            "R.enum.type", f"{field} must be a {enum_type.__name__} member"
        )
    return value


class AccessClass(StrEnum):
    """ASCA project policy access classes, not an official ATLAS classification."""

    PUBLIC = "public"
    INTERNAL = "internal"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return _ACCESS_RANK[self]

    def permits(self, record_class: "AccessClass") -> bool:
        """True when an audience of this class may see a record of ``record_class``."""
        return record_class.rank <= self.rank


_ACCESS_RANK = {AccessClass.PUBLIC: 0, AccessClass.INTERNAL: 1, AccessClass.RESTRICTED: 2}


def most_restrictive(classes: Iterable[AccessClass]) -> AccessClass:
    return max(classes, key=lambda item: item.rank, default=AccessClass.PUBLIC)


class PidScheme(StrEnum):
    DOI = "doi"
    ARXIV = "arxiv"
    INSPIRE = "inspire"
    CDS_REPORT = "cds_report"
    CDS_RECORD = "cds_record"
    GIT_REPOSITORY = "git_repository"
    URL = "url"
    LOCAL_DOCUMENT = "local_document"
    SYNTHETIC = "synthetic"


PUBLISHED_PID_SCHEMES = frozenset(
    {PidScheme.DOI, PidScheme.ARXIV, PidScheme.INSPIRE, PidScheme.CDS_REPORT}
)

_PID_PATTERNS: dict[PidScheme, re.Pattern[str]] = {
    PidScheme.DOI: re.compile(r"10\.\d{4,9}/[^\sA-Z]{1,200}"),
    PidScheme.ARXIV: re.compile(r"(\d{4}\.\d{4,5}|[a-z\-]+(\.[A-Z]{2})?/\d{7})"),
    PidScheme.INSPIRE: re.compile(r"[1-9]\d{0,9}"),
    PidScheme.CDS_REPORT: re.compile(r"[A-Z][A-Z0-9]*(-[A-Z0-9]+){2,6}"),
    PidScheme.CDS_RECORD: re.compile(r"[1-9]\d{0,9}"),
    PidScheme.GIT_REPOSITORY: re.compile(r"https://[A-Za-z0-9.-]+(:\d{1,5})?/[^\s@]{1,1900}"),
    PidScheme.URL: re.compile(r"https://[A-Za-z0-9.-]+(:\d{1,5})?(/[^\s]{0,1900})?"),
    PidScheme.SYNTHETIC: re.compile(r"synthetic:[a-z0-9][a-z0-9-]{0,62}"),
}


def _pid_value_is_valid(scheme: PidScheme, value: str) -> bool:
    if len(value) > PID_MAX:
        return False
    if scheme is PidScheme.LOCAL_DOCUMENT:
        return is_relative_path(value)
    return _PID_PATTERNS[scheme].fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class PersistentIdentifier:
    scheme: PidScheme
    value: str

    def __post_init__(self) -> None:
        require_enum(PidScheme, "persistent_id.scheme", self.scheme)
        if not isinstance(self.value, str) or not _pid_value_is_valid(self.scheme, self.value):
            raise ProvenanceInvariantError(
                "R.pid.format", f"persistent_id value is not a valid {self.scheme.value} value"
            )

    @property
    def is_synthetic(self) -> bool:
        return self.scheme is PidScheme.SYNTHETIC

    @classmethod
    def normalized(cls, scheme: PidScheme, raw: str) -> "PersistentIdentifier":
        value = raw.strip()
        if scheme is PidScheme.DOI:
            value = value.lower()
        return cls(scheme, value)


class LocatorKind(StrEnum):
    PAGE = "page"
    SECTION = "section"
    PARAGRAPH = "paragraph"
    EQUATION = "equation"
    FIGURE = "figure"
    TABLE = "table"
    LINE_RANGE = "line_range"
    PATH = "path"
    ANCHOR = "anchor"


_RANGE_RE = re.compile(r"\d{1,6}(-\d{1,6})?")
LOCATOR_PARTS_MAX = 6


def _range_is_valid(value: str) -> bool:
    if _RANGE_RE.fullmatch(value) is None:
        return False
    start, _, end = value.partition("-")
    first = int(start)
    last = int(end) if end else first
    return 1 <= first <= last


@dataclass(frozen=True, slots=True)
class LocatorPart:
    kind: LocatorKind
    value: str

    def __post_init__(self) -> None:
        require_enum(LocatorKind, "locator.kind", self.kind)
        if self.kind in (LocatorKind.PAGE, LocatorKind.LINE_RANGE):
            valid = isinstance(self.value, str) and _range_is_valid(self.value)
        elif self.kind is LocatorKind.PATH:
            valid = is_relative_path(self.value)
        else:
            try:
                require_text("locator.value", self.value, max_len=SHORT_MAX)
            except ProvenanceInvariantError:
                valid = False
            else:
                valid = True
        if not valid:
            raise ProvenanceInvariantError(
                "R.locator.part", f"locator part value is invalid for kind {self.kind.value}"
            )


@dataclass(frozen=True, slots=True)
class Locator:
    """Ordered locator parts, most specific last."""

    parts: tuple[LocatorPart, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.parts, tuple) or not all(
            isinstance(part, LocatorPart) for part in self.parts
        ):
            raise ProvenanceInvariantError("R.locator.parts", "parts must be a tuple of parts")
        if not 1 <= len(self.parts) <= LOCATOR_PARTS_MAX:
            raise ProvenanceInvariantError(
                "R.locator.parts", f"a locator has 1 to {LOCATOR_PARTS_MAX} parts"
            )
        kinds = [part.kind for part in self.parts]
        if len(set(kinds)) != len(kinds):
            raise ProvenanceInvariantError("R.locator.parts", "locator part kinds must not repeat")

    def has(self, kind: LocatorKind) -> bool:
        return any(part.kind is kind for part in self.parts)
