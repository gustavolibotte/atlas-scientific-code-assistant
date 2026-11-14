"""Projects, sources, source versions and supersession notices."""

import re
from dataclasses import dataclass
from datetime import date, datetime
from enum import StrEnum

from asca.domain.provenance.errors import ProvenanceInvariantError
from asca.domain.provenance.ids import (
    IdKind,
    ProjectId,
    SourceId,
    SourceVersionId,
    SupersessionId,
    optional_id,
    require_id,
)
from asca.domain.provenance.values import (
    STATEMENT_MAX,
    TITLE_MAX,
    AccessClass,
    PersistentIdentifier,
    optional_sha256,
    optional_text,
    optional_utc,
    require_bool,
    require_enum,
    require_text,
    require_utc,
)

VERSION_LABEL_MAX = 100
_COMMIT_RE = re.compile(r"[0-9a-f]{40}([0-9a-f]{24})?")


@dataclass(frozen=True, slots=True)
class Project:
    id: ProjectId
    title: str
    is_synthetic: bool
    created_at: datetime

    def __post_init__(self) -> None:
        require_id(IdKind.PROJECT, self.id, "project.id")
        require_text("project.title", self.title, max_len=TITLE_MAX)
        require_bool("project.is_synthetic", self.is_synthetic)
        require_utc("project.created_at", self.created_at)


class SourceAuthority(StrEnum):
    """Evidence categories are ASCA project policy, not an ATLAS classification."""

    PUBLISHED = "published"
    APPROVED_INTERNAL = "approved_internal"
    VERIFIED_IMPLEMENTATION = "verified_implementation"
    WORKING_MATERIAL = "working_material"
    AUTOMATED_INFERENCE = "automated_inference"

    @property
    def letter(self) -> str:
        return _AUTHORITY_LETTERS[self]

    @property
    def can_support(self) -> bool:
        return self is not SourceAuthority.AUTOMATED_INFERENCE


_AUTHORITY_LETTERS = {
    SourceAuthority.PUBLISHED: "A",
    SourceAuthority.APPROVED_INTERNAL: "B",
    SourceAuthority.VERIFIED_IMPLEMENTATION: "C",
    SourceAuthority.WORKING_MATERIAL: "D",
    SourceAuthority.AUTOMATED_INFERENCE: "E",
}

SYNTHETIC_ALLOWED_AUTHORITIES = frozenset(
    {SourceAuthority.WORKING_MATERIAL, SourceAuthority.AUTOMATED_INFERENCE}
)


@dataclass(frozen=True, slots=True)
class Source:
    id: SourceId
    project_id: ProjectId
    title: str
    persistent_id: PersistentIdentifier
    created_at: datetime

    def __post_init__(self) -> None:
        require_id(IdKind.SOURCE, self.id, "source.id")
        require_id(IdKind.PROJECT, self.project_id, "source.project_id")
        require_text("source.title", self.title, max_len=TITLE_MAX)
        if not isinstance(self.persistent_id, PersistentIdentifier):
            raise ProvenanceInvariantError(
                "R.source.persistent_id", "persistent_id must be a PersistentIdentifier"
            )
        require_utc("source.created_at", self.created_at)

    @property
    def is_synthetic(self) -> bool:
        return self.persistent_id.is_synthetic


@dataclass(frozen=True, slots=True)
class SourceVersion:
    id: SourceVersionId
    project_id: ProjectId
    source_id: SourceId
    version_label: str
    authority: SourceAuthority
    access_class: AccessClass
    access_conditions: str | None
    authority_basis: str | None
    content_sha256: str | None
    retrieved_at: datetime | None
    published_on: date | None
    recorded_at: datetime

    def __post_init__(self) -> None:
        require_id(IdKind.SOURCE_VERSION, self.id, "version.id")
        require_id(IdKind.PROJECT, self.project_id, "version.project_id")
        require_id(IdKind.SOURCE, self.source_id, "version.source_id")
        require_text("version.version_label", self.version_label, max_len=VERSION_LABEL_MAX)
        require_enum(SourceAuthority, "version.authority", self.authority)
        require_enum(AccessClass, "version.access_class", self.access_class)
        optional_text(
            "version.access_conditions",
            self.access_conditions,
            max_len=STATEMENT_MAX,
            multiline=True,
        )
        optional_text(
            "version.authority_basis", self.authority_basis, max_len=STATEMENT_MAX, multiline=True
        )
        optional_sha256("version.content_sha256", self.content_sha256)
        optional_utc("version.retrieved_at", self.retrieved_at)
        require_utc("version.recorded_at", self.recorded_at)
        if self.access_class is not AccessClass.PUBLIC and self.access_conditions is None:
            raise ProvenanceInvariantError(
                "R.version.access_conditions", "non-public versions require access_conditions"
            )
        if self.authority is SourceAuthority.APPROVED_INTERNAL and self.authority_basis is None:
            raise ProvenanceInvariantError(
                "R.version.authority_basis", "approved_internal versions require authority_basis"
            )
        if (self.content_sha256 is None) != (self.retrieved_at is None):
            raise ProvenanceInvariantError(
                "R.version.retrieval_pair", "content_sha256 and retrieved_at are set together"
            )
        if self.authority is SourceAuthority.PUBLISHED and self.access_class is not (
            AccessClass.PUBLIC
        ):
            raise ProvenanceInvariantError(
                "R.version.published_requires_public", "published versions must be public"
            )
        if (
            self.authority is SourceAuthority.VERIFIED_IMPLEMENTATION
            and _COMMIT_RE.fullmatch(self.version_label) is None
        ):
            raise ProvenanceInvariantError(
                "R.version.commit_label",
                "verified_implementation versions are labelled with a full commit hash",
            )
        if self.published_on is not None and (
            not isinstance(self.published_on, date) or isinstance(self.published_on, datetime)
        ):
            raise ProvenanceInvariantError(
                "R.version.published_on", "published_on must be a date, not a datetime"
            )


class SupersessionDimension(StrEnum):
    SCIENTIFIC = "scientific"
    TECHNICAL = "technical"


class Currency(StrEnum):
    """Always derived from supersession notices, never stored."""

    CURRENT = "current"
    SUPERSEDED = "superseded"


@dataclass(frozen=True, slots=True)
class SupersessionNotice:
    id: SupersessionId
    project_id: ProjectId
    superseded_version_id: SourceVersionId
    superseding_version_id: SourceVersionId | None
    dimension: SupersessionDimension
    reason: str
    recorded_at: datetime

    def __post_init__(self) -> None:
        require_id(IdKind.SUPERSESSION, self.id, "supersession.id")
        require_id(IdKind.PROJECT, self.project_id, "supersession.project_id")
        require_id(
            IdKind.SOURCE_VERSION, self.superseded_version_id, "supersession.superseded_version_id"
        )
        optional_id(
            IdKind.SOURCE_VERSION,
            self.superseding_version_id,
            "supersession.superseding_version_id",
        )
        require_enum(SupersessionDimension, "supersession.dimension", self.dimension)
        require_text("supersession.reason", self.reason, max_len=STATEMENT_MAX, multiline=True)
        require_utc("supersession.recorded_at", self.recorded_at)
        if self.superseding_version_id == self.superseded_version_id:
            raise ProvenanceInvariantError(
                "R.supersession.self", "a version cannot supersede itself"
            )
