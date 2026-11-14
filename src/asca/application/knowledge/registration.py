"""Registration planning: turn an assessed candidate into a Source and SourceVersion.

``plan_registration`` is pure and refuses early with clear codes; the M1 graph rules still
apply at commit time. The authority is always an explicit human choice; choosing above the
policy suggestion requires a written basis, and nothing is ever auto-promoted.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, cast

from asca.application.knowledge.federation import AssessedCandidate
from asca.application.knowledge.models import (
    FetchedDocument,
    KnowledgeCandidate,
    PidRole,
    ProviderDescriptor,
)
from asca.application.knowledge.pids import HEPDATA_DOI_PREFIX
from asca.application.knowledge.policy import AUTHORITY_POLICY_VERSION, AuthoritySuggestion
from asca.application.knowledge.text import is_block
from asca.application.provenance import ProvenanceService, SourceDraft, VersionDraft
from asca.domain.provenance import (
    PUBLISHED_PID_SCHEMES,
    STATEMENT_MAX,
    AccessClass,
    PersistentIdentifier,
    PidScheme,
    ProjectId,
    ProvenanceGraph,
    ProvenanceInvariantError,
    SourceAuthority,
    SourceId,
    SourceVersionId,
    sha256_text,
)

CHOICE_TEXT_MAX: Final = 1000


class RefusalCode(StrEnum):
    SYNTHETIC_PROJECT = "synthetic_project"
    NO_PERSISTENT_ID = "no_persistent_id"
    AMBIGUOUS_EXISTING_SOURCES = "ambiguous_existing_sources"
    VERSION_CONFLICT = "version_conflict"
    BASIS_REQUIRED = "basis_required"
    ACCESS_LOWERED = "access_lowered"
    DOCUMENT_MISMATCH = "document_mismatch"
    GENERATED_ONLY_AUTOMATED = "generated_only_automated"
    AUTHORITY_UNSUPPORTED = "authority_unsupported"
    PUBLISHED_NOT_ALLOWED = "published_not_allowed"


_MESSAGES: Final = {
    RefusalCode.SYNTHETIC_PROJECT: "retrieved evidence cannot be registered in a synthetic project",
    RefusalCode.NO_PERSISTENT_ID: "the candidate has no persistent identifier to register",
    RefusalCode.AMBIGUOUS_EXISTING_SOURCES: "the candidate matches more than one existing source",
    RefusalCode.VERSION_CONFLICT: "the source already has this version label with other content",
    RefusalCode.BASIS_REQUIRED: "an authority above the suggestion requires a basis note",
    RefusalCode.ACCESS_LOWERED: "the access class may only stay equal or become more restrictive",
    RefusalCode.DOCUMENT_MISMATCH: "the fetched document does not belong to the candidate",
    RefusalCode.GENERATED_ONLY_AUTOMATED: "generated content can only be automated inference",
    RefusalCode.AUTHORITY_UNSUPPORTED: "this authority cannot be registered from a provider",
    RefusalCode.PUBLISHED_NOT_ALLOWED: "published needs public access and a published identifier",
}


class RegistrationRefused(ValueError):  # noqa: N818 - name fixed by the M3 spec
    """A registration plan was refused; the message is fixed per code."""

    code: RefusalCode

    def __init__(self, code: RefusalCode) -> None:
        super().__init__(f"[{code.value}] {_MESSAGES[code]}")
        self.code = code


@dataclass(frozen=True, slots=True)
class RegistrationChoice:
    authority: SourceAuthority
    """The explicit human choice; there is no default."""
    access_class: AccessClass | None = None
    """None: the candidate's; may only be equal or more restrictive."""
    access_conditions: str | None = None
    basis_note: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.authority, SourceAuthority):
            raise ValueError("choice.authority must be a SourceAuthority")
        if self.access_class is not None and not isinstance(self.access_class, AccessClass):
            raise ValueError("choice.access_class must be an AccessClass")
        for name in ("access_conditions", "basis_note"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, str) or not is_block(value) or len(value) > CHOICE_TEXT_MAX
            ):
                raise ValueError(f"choice.{name} must be clean text of at most 1000 characters")


@dataclass(frozen=True, slots=True)
class RegistrationPlan:
    reuse_source_id: SourceId | None
    source: SourceDraft | None
    """Exactly one of ``reuse_source_id`` and ``source``."""
    version: VersionDraft
    suggestion: AuthoritySuggestion
    idempotent_version_id: SourceVersionId | None
    """Set when the same label and hash already exist: nothing to write."""

    def __post_init__(self) -> None:
        if (self.reuse_source_id is None) == (self.source is None):
            raise ValueError("a plan reuses a source or drafts a new one, never both")
        if self.idempotent_version_id is not None and self.reuse_source_id is None:
            raise ValueError("an idempotent plan reuses an existing source")


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    source_id: SourceId
    version_id: SourceVersionId
    created_source: bool
    created_version: bool


def primary_pid(candidate: KnowledgeCandidate) -> PersistentIdentifier | None:
    """The first match in the registration order among the candidate's pids."""
    identity, related = PidRole.IDENTITY, PidRole.RELATED
    order: tuple[tuple[PidRole | None, PidScheme, bool | None], ...] = (
        (identity, PidScheme.DOI, False),
        (identity, PidScheme.ARXIV, None),
        (identity, PidScheme.INSPIRE, None),
        (identity, PidScheme.CDS_REPORT, None),
        (None, PidScheme.DOI, None),
        (related, PidScheme.LOCAL_DOCUMENT, None),
        (related, PidScheme.URL, None),
    )
    for role, scheme, hepdata in order:
        for item in candidate.pids:
            if (
                (role is None or item.role is role)
                and item.pid.scheme is scheme
                and (hepdata is None or item.pid.value.startswith(HEPDATA_DOI_PREFIX) == hepdata)
            ):
                return item.pid
    return None


def _above(choice: SourceAuthority, suggestion: SourceAuthority) -> bool:
    """Letter order, A best."""
    return choice.letter < suggestion.letter


def _authority_basis(
    assessed: AssessedCandidate,
    descriptor: ProviderDescriptor,
    document: FetchedDocument | None,
    choice: RegistrationChoice,
) -> str:
    suggestion = assessed.suggestion
    candidate = assessed.candidate
    note = " ".join(choice.basis_note.split())[:CHOICE_TEXT_MAX] if choice.basis_note else "none"
    retrieved = document.retrieved_at if document is not None else candidate.retrieved_at
    text = (
        f"ASCA policy {AUTHORITY_POLICY_VERSION} suggested {suggestion.authority.value} "
        f"({suggestion.rule.value}): {suggestion.basis} Chosen: {choice.authority.value} by "
        f"explicit human choice. Note: {note}. Retrieved from provider {descriptor.id} "
        f"({descriptor.kind.value}, adapter {descriptor.adapter_version}) record "
        f"{candidate.ref.native_id} at {retrieved:%Y-%m-%dT%H:%M:%SZ}."
    )
    return text[:STATEMENT_MAX]


def plan_registration(
    graph: ProvenanceGraph,
    assessed: AssessedCandidate,
    descriptor: ProviderDescriptor,
    document: FetchedDocument | None,
    choice: RegistrationChoice,
) -> RegistrationPlan:
    """Plan one registration; raise ``RegistrationRefused``; never write anything."""
    candidate = assessed.candidate
    suggestion = assessed.suggestion
    if graph.project.is_synthetic:
        raise RegistrationRefused(RefusalCode.SYNTHETIC_PROJECT)
    if document is not None and (
        document.ref != candidate.ref or document.access_class is not candidate.access_class
    ):
        raise RegistrationRefused(RefusalCode.DOCUMENT_MISMATCH)

    effective = choice.access_class or candidate.access_class
    primary = primary_pid(candidate)
    authority = choice.authority
    if authority is SourceAuthority.VERIFIED_IMPLEMENTATION:
        raise RegistrationRefused(RefusalCode.AUTHORITY_UNSUPPORTED)
    if candidate.facts.generated and authority is not SourceAuthority.AUTOMATED_INFERENCE:
        raise RegistrationRefused(RefusalCode.GENERATED_ONLY_AUTOMATED)
    if authority is SourceAuthority.PUBLISHED and (
        effective is not AccessClass.PUBLIC
        or primary is None
        or primary.scheme not in PUBLISHED_PID_SCHEMES
        or candidate.facts.generated
    ):
        raise RegistrationRefused(RefusalCode.PUBLISHED_NOT_ALLOWED)
    if (
        _above(authority, suggestion.authority) or authority is SourceAuthority.APPROVED_INTERNAL
    ) and choice.basis_note is None:
        raise RegistrationRefused(RefusalCode.BASIS_REQUIRED)

    if effective.rank < candidate.access_class.rank:
        raise RegistrationRefused(RefusalCode.ACCESS_LOWERED)
    conditions = choice.access_conditions or candidate.access_conditions
    if effective is not AccessClass.PUBLIC and conditions is None:
        raise ProvenanceInvariantError(
            "R.version.access_conditions", "non-public versions require access_conditions"
        )
    if primary is None:
        raise RegistrationRefused(RefusalCode.NO_PERSISTENT_ID)

    matches = {primary, *candidate.identity_pids}
    existing = [source for source in graph.sources if source.persistent_id in matches]
    if len(existing) > 1:
        raise RegistrationRefused(RefusalCode.AMBIGUOUS_EXISTING_SOURCES)
    reuse = existing[0].id if existing else None

    label = candidate.version.label
    idempotent: SourceVersionId | None = None
    if reuse is not None:
        digest = sha256_text(document.text) if document is not None else None
        for version in graph.versions:
            if version.source_id == reuse and version.version_label == label:
                if version.content_sha256 != digest:
                    raise RegistrationRefused(RefusalCode.VERSION_CONFLICT)
                idempotent = version.id

    draft = VersionDraft(
        version_label=label,
        authority=authority,
        access_class=effective,
        access_conditions=conditions,
        authority_basis=_authority_basis(assessed, descriptor, document, choice),
        content_text=document.text if document is not None else None,
        published_on=candidate.issued.as_date() if candidate.issued is not None else None,
        retrieved_at=document.retrieved_at if document is not None else None,
    )
    return RegistrationPlan(
        reuse_source_id=reuse,
        source=None if reuse is not None else SourceDraft(candidate.title, primary),
        version=draft,
        suggestion=suggestion,
        idempotent_version_id=idempotent,
    )


class KnowledgeRegistrationService:
    def __init__(self, provenance: ProvenanceService) -> None:
        self._provenance = provenance

    def register(
        self,
        project_id: ProjectId,
        assessed: AssessedCandidate,
        descriptor: ProviderDescriptor,
        document: FetchedDocument | None,
        choice: RegistrationChoice,
    ) -> RegistrationResult:
        """Plan, then write the source and version in one atomic commit (or nothing)."""
        graph = self._provenance.load(project_id)
        plan = plan_registration(graph, assessed, descriptor, document, choice)
        target: SourceDraft | SourceId
        if plan.reuse_source_id is not None:
            if plan.idempotent_version_id is not None:
                return RegistrationResult(
                    plan.reuse_source_id, plan.idempotent_version_id, False, False
                )
            target = plan.reuse_source_id
        else:
            target = cast(SourceDraft, plan.source)
        source_id, version_id = self._provenance.record_source_version(
            project_id, target, plan.version
        )
        return RegistrationResult(source_id, version_id, plan.source is not None, True)
