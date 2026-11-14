"""Persistent-identifier normalisers, the PID sort key and identity rules.

Normalisers return ``None`` when a value is not recognised; the caller drops and counts
the item. They never guess.
"""

import re
from enum import StrEnum
from typing import Final
from urllib.parse import unquote

from asca.domain.provenance import PersistentIdentifier, PidScheme


class PidRole(StrEnum):
    IDENTITY = "identity"
    RELATED = "related"


IDENTITY_SCHEMES: Final = frozenset(
    {PidScheme.DOI, PidScheme.ARXIV, PidScheme.INSPIRE, PidScheme.CDS_REPORT}
)
SCHEME_ORDER: Final = (
    PidScheme.DOI,
    PidScheme.ARXIV,
    PidScheme.INSPIRE,
    PidScheme.CDS_REPORT,
    PidScheme.CDS_RECORD,
    PidScheme.LOCAL_DOCUMENT,
    PidScheme.URL,
)
HEPDATA_DOI_PREFIX: Final = "10.17182/hepdata."
IDENTITY_REPORT_PREFIXES: Final = ("ATLAS-", "ATL-", "CERN-")

_DOI_PREFIXES = (
    "doi:",
    "https://doi.org/",
    "http://doi.org/",
    "https://dx.doi.org/",
    "http://dx.doi.org/",
)
_ARXIV_PREFIXES = ("arxiv:", "https://arxiv.org/abs/", "http://arxiv.org/abs/")
_ARXIV_VERSION_RE = re.compile(r"(?P<id>.+?)v(?P<v>[1-9]\d{0,3})")
_ARXIV_NEW_RE = re.compile(r"(?P<yy>\d{2})(?P<mm>\d{2})\.(?P<num>\d{4,5})")
_ARXIV_OLD_RE = re.compile(r"[a-z][a-z-]*(\.[A-Z]{2})?/\d{7}")
_INSPIRE_RE = re.compile(r"[1-9]\d{0,9}")
_HEPDATA_RE = re.compile(r"10\.17182/hepdata\.(?P<n>\d{1,9})\.v(?P<v>[1-9]\d{0,3})(/.*)?")
_RANK = {scheme: index for index, scheme in enumerate(SCHEME_ORDER)}


def pid_sort_key(pid: PersistentIdentifier) -> tuple[int, str]:
    """DOI before arXiv before INSPIRE before CDS report, ...; then by value."""
    return (_RANK.get(pid.scheme, len(SCHEME_ORDER)), pid.value)


def pid_text(pid: PersistentIdentifier) -> str:
    return f"{pid.scheme.value}:{pid.value}"


def _make(scheme: PidScheme, value: str) -> PersistentIdentifier | None:
    try:
        return PersistentIdentifier(scheme, value)
    except ValueError:
        return None


def _strip_prefix(value: str, prefixes: tuple[str, ...]) -> tuple[str, str | None]:
    lowered = value.lower()
    for prefix in prefixes:
        if lowered.startswith(prefix):
            return value[len(prefix) :], prefix
    return value, None


def normalize_doi(raw: str) -> PersistentIdentifier | None:
    if not isinstance(raw, str):
        return None
    value, prefix = _strip_prefix(raw.strip(), _DOI_PREFIXES)
    if prefix is not None and prefix != "doi:":
        value = unquote(value)
    return _make(PidScheme.DOI, value.lower())


def normalize_arxiv(raw: str) -> tuple[PersistentIdentifier, int | None] | None:
    """Return the version-free arXiv pid and the version number when one was given."""
    if not isinstance(raw, str):
        return None
    value, _ = _strip_prefix(raw.strip(), _ARXIV_PREFIXES)
    version: int | None = None
    split = _ARXIV_VERSION_RE.fullmatch(value)
    if split is not None:
        value, version = split["id"], int(split["v"])
    new_style = _ARXIV_NEW_RE.fullmatch(value)
    if new_style is not None:
        month = int(new_style["mm"])
        yymm = int(new_style["yy"] + new_style["mm"])
        digits = 4 if yymm < 1501 else 5
        if not 1 <= month <= 12 or len(new_style["num"]) != digits:
            return None
    elif _ARXIV_OLD_RE.fullmatch(value) is None:
        return None
    pid = _make(PidScheme.ARXIV, value)
    return None if pid is None else (pid, version)


def normalize_inspire(raw: int | str) -> PersistentIdentifier | None:
    if isinstance(raw, bool) or not isinstance(raw, int | str):
        return None
    value = str(raw)
    if _INSPIRE_RE.fullmatch(value) is None:
        return None
    return _make(PidScheme.INSPIRE, value)


def normalize_report_number(raw: str) -> tuple[PersistentIdentifier, PidRole] | None:
    if not isinstance(raw, str):
        return None
    pid = _make(PidScheme.CDS_REPORT, raw.strip().upper())
    if pid is None:
        return None
    identity = pid.value.startswith(IDENTITY_REPORT_PREFIXES)
    return pid, PidRole.IDENTITY if identity else PidRole.RELATED


def split_hepdata_doi(doi: PersistentIdentifier) -> tuple[PersistentIdentifier, int] | None:
    """``10.17182/hepdata.N.vK[/...]`` -> (concept DOI ``10.17182/hepdata.N``, K)."""
    if doi.scheme is not PidScheme.DOI:
        return None
    match = _HEPDATA_RE.fullmatch(doi.value)
    if match is None:
        return None
    concept = _make(PidScheme.DOI, f"{HEPDATA_DOI_PREFIX}{match['n']}")
    return None if concept is None else (concept, int(match["v"]))


def parse_pid_text(text: str) -> PersistentIdentifier | None:
    """Parse ``scheme:value`` for the identity schemes (doi, arxiv, inspire, cds_report)."""
    if not isinstance(text, str):
        return None
    scheme, separator, value = text.strip().partition(":")
    if not separator:
        return None
    scheme = scheme.lower()
    if scheme == PidScheme.DOI.value:
        return normalize_doi(value)
    if scheme == PidScheme.ARXIV.value:
        arxiv = normalize_arxiv(value)
        return None if arxiv is None else arxiv[0]
    if scheme == PidScheme.INSPIRE.value:
        return normalize_inspire(value.strip())
    if scheme == PidScheme.CDS_REPORT.value:
        report = normalize_report_number(value)
        return None if report is None else report[0]
    return None
