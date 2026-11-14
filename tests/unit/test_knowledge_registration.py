"""Registration planning and the atomic source-plus-version write."""

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta

import pytest
from knowledge_contract import (
    RETRIEVED_AT,
    identity,
    make_candidate,
    make_descriptor,
    make_document,
    related,
)
from provenance_builders import CountingIdFactory, StepClock

from asca.application.knowledge.federation import AssessedCandidate
from asca.application.knowledge.models import (
    CandidateVersion,
    KnowledgeCandidate,
    PartialDate,
    PidOrigin,
    ProviderDescriptor,
    ProviderKind,
    VersionKind,
)
from asca.application.knowledge.policy import suggest_authority
from asca.application.knowledge.registration import (
    KnowledgeRegistrationService,
    RefusalCode,
    RegistrationChoice,
    RegistrationPlan,
    RegistrationRefused,
    RegistrationResult,
    plan_registration,
    primary_pid,
)
from asca.application.provenance import ProvenanceService, SourceDraft, VersionDraft
from asca.domain.provenance import (
    AccessClass,
    PersistentIdentifier,
    PidScheme,
    ProjectId,
    ProvenanceInvariantError,
    SourceAuthority,
)
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository

pytestmark = pytest.mark.unit

A = SourceAuthority.PUBLISHED
B = SourceAuthority.APPROVED_INTERNAL
D = SourceAuthority.WORKING_MATERIAL
E = SourceAuthority.AUTOMATED_INFERENCE
DOI = "doi:10.5555/asca-test.1"
ARXIV = "arxiv:2109.05124"
NOW = datetime(2026, 11, 15, tzinfo=UTC)
TEXT = "Synthetic title\n\nOptimal filtering minimises the noise variance.\n"


def service() -> ProvenanceService:
    return ProvenanceService(InMemoryProvenanceRepository(), StepClock(NOW), CountingIdFactory())


def project(provenance: ProvenanceService, *, synthetic: bool = False) -> ProjectId:
    return provenance.create_project("Registration fixture project", is_synthetic=synthetic)


def inspire(refereed: bool | None = True) -> KnowledgeCandidate:
    return make_candidate(
        ProviderKind.INSPIRE,
        "1920956",
        refereed=refereed,
        issued=PartialDate(2022, 1, 4),
        pids=[identity("inspire:1920956", PidOrigin.NATIVE), identity(DOI), identity(ARXIV)],
    )


def inspire_journal() -> KnowledgeCandidate:
    return replace(
        inspire(), version=CandidateVersion(VersionKind.JOURNAL_PUBLICATION, f"doi:{DOI[4:]}")
    )


def arxiv() -> KnowledgeCandidate:
    return make_candidate(
        ProviderKind.ARXIV,
        "2109.05124v2",
        issued=PartialDate(2021, 9),
        pids=[
            identity(ARXIV, PidOrigin.NATIVE),
            identity(DOI, PidOrigin.PROVIDER_ASSERTED),
        ],
    )


def internal_local(authority: SourceAuthority = D) -> KnowledgeCandidate:
    return make_candidate(
        ProviderKind.LOCAL,
        "notes/a.md",
        access_class=AccessClass.INTERNAL,
        declared_authority=authority,
        pids=[related("local_document:notes/a.md", PidOrigin.NATIVE)],
    )


def mcp(generated: bool = False, *, url: bool = True) -> KnowledgeCandidate:
    pids = [related("url:https://example.org/asca-test/doc", PidOrigin.PROVIDER_ASSERTED)]
    return make_candidate(
        ProviderKind.MCP,
        "doc-1",
        access_class=AccessClass.INTERNAL,
        generated=generated,
        declared_authority=E if generated else D,
        pids=pids if url else [],
    )


def assess(candidate: KnowledgeCandidate) -> AssessedCandidate:
    return AssessedCandidate(candidate, suggest_authority(candidate))


def descriptor_for(candidate: KnowledgeCandidate) -> ProviderDescriptor:
    access = candidate.access_class if candidate.kind is ProviderKind.MCP else AccessClass.PUBLIC
    return make_descriptor(candidate.kind, candidate.ref.provider_id, access_class=access)


def plan(
    provenance: ProvenanceService,
    pid: ProjectId,
    candidate: KnowledgeCandidate,
    choice: RegistrationChoice,
    *,
    text: str | None = None,
) -> RegistrationPlan:
    document = make_document(candidate, text) if text is not None else None
    return plan_registration(
        provenance.load(pid), assess(candidate), descriptor_for(candidate), document, choice
    )


def refused(code: RefusalCode, call: Callable[[], object]) -> None:
    with pytest.raises(RegistrationRefused) as caught:
        call()
    assert caught.value.code is code
    assert code.value in str(caught.value)


def register(
    registrar: KnowledgeRegistrationService,
    pid: ProjectId,
    candidate: KnowledgeCandidate,
    choice: RegistrationChoice,
    text: str | None = TEXT,
) -> RegistrationResult:
    document = make_document(candidate, text) if text is not None else None
    return registrar.register(pid, assess(candidate), descriptor_for(candidate), document, choice)


# ---------------------------------------------------------------------- refusals


def test_choice_above_the_suggestion_requires_a_basis() -> None:
    provenance = service()
    pid = project(provenance)
    unrefereed = inspire(refereed=None)
    refused(
        RefusalCode.BASIS_REQUIRED, lambda: plan(provenance, pid, unrefereed, RegistrationChoice(A))
    )
    with_note = plan(
        provenance,
        pid,
        unrefereed,
        RegistrationChoice(A, basis_note="Checked the journal version."),
    )
    assert with_note.version.authority is A
    assert "Note: Checked the journal version." in (with_note.version.authority_basis or "")
    assert plan(provenance, pid, inspire(), RegistrationChoice(A)).version.authority is A
    assert plan(provenance, pid, unrefereed, RegistrationChoice(E)).version.authority is E


def test_approved_internal_always_requires_a_basis() -> None:
    provenance = service()
    pid = project(provenance)
    candidate = internal_local()
    refused(
        RefusalCode.BASIS_REQUIRED, lambda: plan(provenance, pid, candidate, RegistrationChoice(B))
    )
    ok = plan(
        provenance, pid, candidate, RegistrationChoice(B, basis_note="Approved in the group.")
    )
    assert ok.version.authority is B


def test_access_may_never_be_lowered() -> None:
    provenance = service()
    pid = project(provenance)
    candidate = internal_local()
    refused(
        RefusalCode.ACCESS_LOWERED,
        lambda: plan(
            provenance, pid, candidate, RegistrationChoice(D, access_class=AccessClass.PUBLIC)
        ),
    )
    raised = plan(
        provenance,
        pid,
        candidate,
        RegistrationChoice(D, access_class=AccessClass.RESTRICTED, access_conditions="Two people."),
    )
    assert raised.version.access_class is AccessClass.RESTRICTED
    assert raised.version.access_conditions == "Two people."


def test_raising_public_access_needs_conditions() -> None:
    provenance = service()
    pid = project(provenance)
    with pytest.raises(ProvenanceInvariantError):
        plan(provenance, pid, inspire(), RegistrationChoice(D, access_class=AccessClass.INTERNAL))


def test_synthetic_projects_are_refused() -> None:
    provenance = service()
    pid = project(provenance, synthetic=True)
    refused(
        RefusalCode.SYNTHETIC_PROJECT,
        lambda: plan(provenance, pid, inspire(), RegistrationChoice(A)),
    )


def test_published_needs_public_access_and_a_published_pid() -> None:
    provenance = service()
    pid = project(provenance)
    refused(
        RefusalCode.PUBLISHED_NOT_ALLOWED,
        lambda: plan(provenance, pid, mcp(), RegistrationChoice(A, basis_note="Looks published.")),
    )
    published_hint = make_candidate(
        ProviderKind.LOCAL,
        "notes/p.md",
        access_class=AccessClass.INTERNAL,
        declared_authority=A,
        pids=[identity(DOI), related("local_document:notes/p.md", PidOrigin.NATIVE)],
    )
    refused(
        RefusalCode.PUBLISHED_NOT_ALLOWED,
        lambda: plan(provenance, pid, published_hint, RegistrationChoice(A, basis_note="Journal.")),
    )


def test_generated_content_is_only_automated_inference() -> None:
    provenance = service()
    pid = project(provenance)
    refused(
        RefusalCode.GENERATED_ONLY_AUTOMATED,
        lambda: plan(provenance, pid, mcp(generated=True), RegistrationChoice(D, basis_note="x")),
    )
    ok = plan(provenance, pid, mcp(generated=True), RegistrationChoice(E))
    assert ok.version.authority is E


def test_verified_implementation_is_unsupported() -> None:
    provenance = service()
    pid = project(provenance)
    choice = RegistrationChoice(SourceAuthority.VERIFIED_IMPLEMENTATION, basis_note="x")
    refused(RefusalCode.AUTHORITY_UNSUPPORTED, lambda: plan(provenance, pid, inspire(), choice))


def test_document_must_belong_to_the_candidate() -> None:
    provenance = service()
    pid = project(provenance)
    graph = provenance.load(pid)
    candidate = inspire()
    foreign = make_document(arxiv())
    refused(
        RefusalCode.DOCUMENT_MISMATCH,
        lambda: plan_registration(
            graph, assess(candidate), descriptor_for(candidate), foreign, RegistrationChoice(A)
        ),
    )
    local_candidate = internal_local()
    public_doc = replace(
        make_document(local_candidate), access_class=AccessClass.PUBLIC, access_conditions=None
    )
    refused(
        RefusalCode.DOCUMENT_MISMATCH,
        lambda: plan_registration(
            graph,
            assess(local_candidate),
            descriptor_for(local_candidate),
            public_doc,
            RegistrationChoice(D),
        ),
    )


def test_candidate_without_any_pid_is_refused() -> None:
    provenance = service()
    pid = project(provenance)
    refused(
        RefusalCode.NO_PERSISTENT_ID,
        lambda: plan(provenance, pid, mcp(url=False), RegistrationChoice(D)),
    )


def test_ambiguous_existing_sources_are_refused() -> None:
    provenance = service()
    pid = project(provenance)
    provenance.register_source(
        pid, SourceDraft("By DOI", PersistentIdentifier(PidScheme.DOI, DOI[4:]))
    )
    provenance.register_source(
        pid, SourceDraft("By arXiv", PersistentIdentifier(PidScheme.ARXIV, ARXIV[6:]))
    )
    refused(
        RefusalCode.AMBIGUOUS_EXISTING_SOURCES,
        lambda: plan(provenance, pid, inspire(), RegistrationChoice(A)),
    )


# ---------------------------------------------------------------------- plans and writes


def test_primary_pid_order() -> None:
    def primary(candidate: KnowledgeCandidate) -> str | None:
        found = primary_pid(candidate)
        return None if found is None else f"{found.scheme.value}:{found.value}"

    assert primary(inspire()) == DOI
    assert primary(arxiv()) == DOI
    assert (
        primary(
            make_candidate(ProviderKind.ARXIV, "2302.07555v2", pids=[identity("arxiv:2302.07555")])
        )
        == "arxiv:2302.07555"
    )
    assert primary(make_candidate(pids=[identity("inspire:2744105")])) == "inspire:2744105"
    assert (
        primary(
            make_candidate(pids=[identity("cds_report:ATLAS-CONF-2023-001"), related("inspire:5")])
        )
        == "cds_report:ATLAS-CONF-2023-001"
    )
    hepdata = make_candidate(
        ProviderKind.HEPDATA,
        "ins1",
        pids=[identity("doi:10.17182/hepdata.1", PidOrigin.NATIVE), related("inspire:1")],
    )
    assert primary(hepdata) == "doi:10.17182/hepdata.1"
    assert primary(internal_local()) == "local_document:notes/a.md"
    assert primary(mcp()) == "url:https://example.org/asca-test/doc"
    assert primary(mcp(url=False)) is None


def test_published_on_only_with_day_precision() -> None:
    provenance = service()
    pid = project(provenance)
    assert plan(provenance, pid, inspire(), RegistrationChoice(A)).version.published_on == date(
        2022, 1, 4
    )
    assert plan(provenance, pid, arxiv(), RegistrationChoice(D)).version.published_on is None
    assert plan(provenance, pid, mcp(), RegistrationChoice(D)).version.published_on is None


def test_authority_basis_template_is_bounded() -> None:
    provenance = service()
    pid = project(provenance)
    note = "Long reason.\n" + "x" * 980
    candidate = replace(inspire(refereed=None), ref=replace(inspire().ref, native_id="1920956"))
    draft = plan(
        provenance, pid, candidate, RegistrationChoice(A, basis_note=note), text=TEXT
    ).version
    basis = draft.authority_basis or ""
    assert len(basis) <= 2000
    assert "\n" not in basis
    assert basis.startswith(
        "ASCA policy asca-authority/1 suggested working_material (inspire.other/1): "
        "INSPIRE record 1920956 is not marked refereed with a DOI. Chosen: published by "
        "explicit human choice. Note: Long reason. xxx"
    )
    assert basis.endswith(
        "Retrieved from provider inspire (inspire, adapter inspire/1) record 1920956 at "
        "2026-11-14T10:00:00Z."
    )
    assert draft.retrieved_at == RETRIEVED_AT
    assert draft.content_text == TEXT
    no_doc = plan(provenance, pid, inspire(), RegistrationChoice(A)).version
    assert "Note: none." in (no_doc.authority_basis or "")
    assert no_doc.retrieved_at is None and no_doc.content_text is None


def test_registration_reuses_a_source_through_an_identity_pid() -> None:
    provenance = service()
    pid = project(provenance)
    registrar = KnowledgeRegistrationService(provenance)
    first_candidate = make_candidate(
        ProviderKind.ARXIV, "2109.05124v2", pids=[identity(ARXIV, PidOrigin.NATIVE)]
    )
    first = register(registrar, pid, first_candidate, RegistrationChoice(D))
    second = register(registrar, pid, inspire_journal(), RegistrationChoice(A))
    assert first.created_source and first.created_version
    assert second.source_id == first.source_id
    assert not second.created_source and second.created_version
    graph = provenance.load(pid)
    assert len(graph.sources) == 1
    assert graph.sources[0].persistent_id == PersistentIdentifier(PidScheme.ARXIV, ARXIV[6:])
    assert sorted(v.version_label for v in graph.versions) == [
        "arXiv:2109.05124v2",
        f"doi:{DOI[4:]}",
    ]


def test_same_label_and_hash_is_idempotent_and_other_content_conflicts() -> None:
    provenance = service()
    pid = project(provenance)
    registrar = KnowledgeRegistrationService(provenance)
    first = register(registrar, pid, inspire_journal(), RegistrationChoice(A))
    revision = provenance.list_projects()[0].revision
    again = register(registrar, pid, inspire_journal(), RegistrationChoice(A))
    assert again.source_id == first.source_id and again.version_id == first.version_id
    assert not again.created_source and not again.created_version
    assert provenance.list_projects()[0].revision == revision
    refused(
        RefusalCode.VERSION_CONFLICT,
        lambda: register(registrar, pid, inspire_journal(), RegistrationChoice(A), text="Other.\n"),
    )
    refused(
        RefusalCode.VERSION_CONFLICT,
        lambda: register(registrar, pid, inspire_journal(), RegistrationChoice(A), text=None),
    )


def test_metadata_only_registration_is_idempotent_too() -> None:
    provenance = service()
    pid = project(provenance)
    registrar = KnowledgeRegistrationService(provenance)
    first = register(registrar, pid, inspire(), RegistrationChoice(A), text=None)
    again = register(registrar, pid, inspire(), RegistrationChoice(A), text=None)
    assert again.version_id == first.version_id and not again.created_version


def test_registration_choice_and_plan_validation() -> None:
    for bad in (
        {"authority": "published"},
        {"access_class": "public"},
        {"access_conditions": ""},
        {"basis_note": "x" * 1001},
        {"basis_note": "esc\x1b"},
    ):
        with pytest.raises(ValueError):
            RegistrationChoice(**{"authority": A, **bad})  # type: ignore[arg-type]
    provenance = service()
    pid = project(provenance)
    good = plan(provenance, pid, inspire(), RegistrationChoice(A))
    with pytest.raises(ValueError):
        replace(good, reuse_source_id=None, source=None)
    with pytest.raises(ValueError):
        replace(good, idempotent_version_id=good.version.version_label)  # type: ignore[arg-type]


# ---------------------------------------------------------------------- provenance edits


def test_record_source_version_is_atomic() -> None:
    provenance = service()
    pid = project(provenance)
    before = provenance.list_projects()[0].revision
    bad_version = VersionDraft("v1", A, AccessClass.INTERNAL, access_conditions="Internal.")
    with pytest.raises(ProvenanceInvariantError):
        provenance.record_source_version(
            pid, SourceDraft("Fixture", PersistentIdentifier(PidScheme.DOI, DOI[4:])), bad_version
        )
    graph = provenance.load(pid)
    assert graph.sources == () and graph.versions == ()
    assert provenance.list_projects()[0].revision == before


def test_record_source_version_creates_or_reuses_in_one_commit() -> None:
    provenance = service()
    pid = project(provenance)
    draft = SourceDraft("Fixture", PersistentIdentifier(PidScheme.DOI, DOI[4:]))
    source_id, first = provenance.record_source_version(
        pid, draft, VersionDraft("v1", D, AccessClass.PUBLIC)
    )
    assert provenance.list_projects()[0].revision == 1
    same, second = provenance.record_source_version(
        pid, source_id, VersionDraft("v2", D, AccessClass.PUBLIC)
    )
    assert same == source_id and second != first
    assert provenance.list_projects()[0].revision == 2


def test_version_draft_retrieved_at_rules() -> None:
    provenance = service()
    pid = project(provenance)
    source = provenance.register_source(
        pid, SourceDraft("Fixture", PersistentIdentifier(PidScheme.DOI, DOI[4:]))
    )
    good = VersionDraft("v1", D, AccessClass.PUBLIC, content_text=TEXT, retrieved_at=RETRIEVED_AT)
    version_id = provenance.add_source_version(pid, source, good)
    stored = next(v for v in provenance.load(pid).versions if v.id == version_id)
    assert stored.retrieved_at == RETRIEVED_AT
    defaulted = provenance.add_source_version(
        pid, source, VersionDraft("v2", D, AccessClass.PUBLIC, content_text=TEXT)
    )
    stored = next(v for v in provenance.load(pid).versions if v.id == defaulted)
    assert stored.retrieved_at is not None and stored.retrieved_at > RETRIEVED_AT
    for bad in (
        VersionDraft("v3", D, AccessClass.PUBLIC, retrieved_at=RETRIEVED_AT),
        VersionDraft(
            "v3", D, AccessClass.PUBLIC, content_text=TEXT, retrieved_at=datetime(2026, 1, 1)
        ),
        VersionDraft(
            "v3", D, AccessClass.PUBLIC, content_text=TEXT, retrieved_at=NOW + timedelta(days=30)
        ),
    ):
        with pytest.raises(ProvenanceInvariantError, match=r"R\.draft\.retrieved_at"):
            provenance.add_source_version(pid, source, bad)
