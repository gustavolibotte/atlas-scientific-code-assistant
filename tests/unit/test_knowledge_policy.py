"""Authority suggestion policy asca-authority/1."""

import pytest
from hypothesis import given
from hypothesis import strategies as st
from knowledge_contract import identity, make_candidate, related

from asca.application.knowledge.models import (
    CandidateVersion,
    KnowledgeCandidate,
    PidOrigin,
    ProviderKind,
    VersionKind,
)
from asca.application.knowledge.policy import (
    AuthorityRule,
    AuthoritySuggestion,
    suggest_authority,
)
from asca.domain.provenance import PUBLISHED_PID_SCHEMES, AccessClass, SourceAuthority

pytestmark = pytest.mark.unit

A, D, E = (
    SourceAuthority.PUBLISHED,
    SourceAuthority.WORKING_MATERIAL,
    SourceAuthority.AUTOMATED_INFERENCE,
)
JOURNAL_DOI = "doi:10.1088/1748-0221/17/01/p01002"


def _inspire(
    refereed: bool | None, *pids: str, origin: PidOrigin = PidOrigin.CURATED_LINK
) -> KnowledgeCandidate:
    return make_candidate(
        ProviderKind.INSPIRE,
        "1920956",
        refereed=refereed,
        pids=[identity("inspire:1920956", PidOrigin.NATIVE), *(identity(p, origin) for p in pids)],
    )


def test_refereed_inspire_record_with_a_curated_doi_is_published() -> None:
    suggestion = suggest_authority(_inspire(True, JOURNAL_DOI, "arxiv:2109.05124"))
    assert suggestion == AuthoritySuggestion(
        A,
        AuthorityRule.INSPIRE_REFEREED,
        "Refereed INSPIRE record 1920956 lists DOI 10.1088/1748-0221/17/01/p01002.",
    )


@pytest.mark.parametrize("refereed", [None, False])
def test_unrefereed_inspire_record_is_working_material(refereed: bool | None) -> None:
    suggestion = suggest_authority(_inspire(refereed, JOURNAL_DOI))
    assert (suggestion.authority, suggestion.rule) == (D, AuthorityRule.INSPIRE_OTHER)
    assert suggestion.basis == "INSPIRE record 1920956 is not marked refereed with a DOI."


def test_inspire_published_needs_a_curated_non_hepdata_doi() -> None:
    no_doi = _inspire(True, "arxiv:2109.05124")
    hepdata = _inspire(True, "doi:10.17182/hepdata.1.v1")
    asserted = _inspire(True, JOURNAL_DOI, origin=PidOrigin.PROVIDER_ASSERTED)
    for candidate in (no_doi, hepdata, asserted):
        assert suggest_authority(candidate).authority is D


def test_inspire_basis_falls_back_to_the_native_id() -> None:
    candidate = make_candidate(ProviderKind.INSPIRE, "2744105")
    assert "2744105" in suggest_authority(candidate).basis


def test_arxiv_preprint_with_a_doi_stays_working_material() -> None:
    candidate = make_candidate(
        ProviderKind.ARXIV,
        "2109.05124v2",
        pids=[
            identity("arxiv:2109.05124", PidOrigin.NATIVE),
            identity(JOURNAL_DOI, PidOrigin.PROVIDER_ASSERTED),
        ],
    )
    suggestion = suggest_authority(candidate)
    assert (suggestion.authority, suggestion.rule) == (D, AuthorityRule.ARXIV_PREPRINT)
    assert suggestion.basis == (
        "arXiv preprint 2109.05124v2. Author-supplied DOI 10.1088/1748-0221/17/01/p01002."
    )
    plain = make_candidate(ProviderKind.ARXIV, "2302.07555v2")
    assert suggest_authority(plain).basis == "arXiv preprint 2302.07555v2."


def test_long_basis_is_truncated_to_300_characters() -> None:
    doi = "doi:10.5555/" + "x" * 195
    candidate = make_candidate(
        ProviderKind.ARXIV,
        "2109.05124v2",
        version=CandidateVersion(VersionKind.ARXIV_VERSION, "arXiv:2109.05124v2"),
        pids=[identity(doi, PidOrigin.PROVIDER_ASSERTED)],
    )
    basis = suggest_authority(candidate).basis
    assert len(basis) <= 300


def test_hepdata_is_working_material() -> None:
    candidate = make_candidate(
        ProviderKind.HEPDATA,
        "ins1",
        pids=[identity("doi:10.17182/hepdata.1", PidOrigin.NATIVE), related("inspire:1")],
    )
    suggestion = suggest_authority(candidate)
    assert suggestion == AuthoritySuggestion(
        D, AuthorityRule.HEPDATA_DATASET, "HEPData record 10.17182/hepdata.1."
    )


def _local(
    authority: SourceAuthority, access: AccessClass = AccessClass.PUBLIC, *pids: str
) -> KnowledgeCandidate:
    return make_candidate(
        ProviderKind.LOCAL,
        "notes/a.md",
        declared_authority=authority,
        access_class=access,
        pids=[identity(p) for p in pids] + [related("local_document:notes/a.md", PidOrigin.NATIVE)],
    )


def test_local_published_with_a_public_published_pid_is_published() -> None:
    suggestion = suggest_authority(_local(A, AccessClass.PUBLIC, JOURNAL_DOI))
    assert (suggestion.authority, suggestion.rule) == (A, AuthorityRule.LOCAL_DECLARED)
    assert JOURNAL_DOI in suggestion.basis


def test_local_published_hint_is_downgraded_without_pid_or_public_access() -> None:
    for candidate in (_local(A), _local(A, AccessClass.INTERNAL, JOURNAL_DOI)):
        suggestion = suggest_authority(candidate)
        assert (suggestion.authority, suggestion.rule) == (D, AuthorityRule.LOCAL_DOWNGRADED)


def test_local_declared_working_material_and_automated() -> None:
    assert suggest_authority(_local(D)).authority is D
    automated = suggest_authority(_local(E))
    assert (automated.authority, automated.rule) == (E, AuthorityRule.LOCAL_DECLARED)


def test_mcp_documents_and_generated_answers() -> None:
    document = make_candidate(ProviderKind.MCP, "doc-1", access_class=AccessClass.INTERNAL)
    suggestion = suggest_authority(document)
    assert (suggestion.authority, suggestion.rule) == (D, AuthorityRule.MCP_DOCUMENT)
    assert suggestion.basis == "Document from MCP provider mcp:test."
    automated = make_candidate(ProviderKind.MCP, "doc-2", declared_authority=E)
    assert suggest_authority(automated).authority is E
    generated = make_candidate(ProviderKind.MCP, "doc-3", generated=True, declared_authority=E)
    assert suggest_authority(generated) == AuthoritySuggestion(
        E, AuthorityRule.MCP_GENERATED, "Model-generated answer from an MCP tool."
    )


def test_suggestion_type_refuses_b_and_c() -> None:
    for authority in (SourceAuthority.APPROVED_INTERNAL, SourceAuthority.VERIFIED_IMPLEMENTATION):
        with pytest.raises(ValueError):
            AuthoritySuggestion(authority, AuthorityRule.LOCAL_DECLARED, "basis")
    with pytest.raises(ValueError):
        AuthoritySuggestion(A, "inspire.refereed/1", "basis")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        AuthoritySuggestion(A, AuthorityRule.INSPIRE_REFEREED, "x" * 301)


IDENTITY_TEXTS = st.sampled_from(
    [
        JOURNAL_DOI,
        "doi:10.17182/hepdata.1",
        "arxiv:2109.05124",
        "inspire:1",
        "cds_report:ATLAS-CONF-2023-001",
    ]
)


NATIVE_IDS = {
    ProviderKind.INSPIRE: "1",
    ProviderKind.ARXIV: "2109.05124v2",
    ProviderKind.HEPDATA: "ins1",
    ProviderKind.LOCAL: "notes/a.md",
    ProviderKind.MCP: "doc-1",
}


@st.composite
def candidates(draw: st.DrawFn) -> KnowledgeCandidate:
    kind = draw(st.sampled_from(list(ProviderKind)))
    access = draw(st.sampled_from(list(AccessClass)))
    if kind not in (ProviderKind.LOCAL, ProviderKind.MCP):
        access = AccessClass.PUBLIC
    generated = kind is ProviderKind.MCP and draw(st.booleans())
    declared = None
    if kind is ProviderKind.LOCAL:
        declared = draw(st.sampled_from([A, D, E]))
    elif kind is ProviderKind.MCP:
        declared = E if generated else draw(st.sampled_from([D, E]))
    texts = draw(st.lists(IDENTITY_TEXTS, unique=True, max_size=4))
    origin = draw(st.sampled_from(list(PidOrigin)))
    if kind is ProviderKind.MCP:
        pids = [related(text, origin) for text in texts]
    else:
        pids = [identity(text, origin) for text in texts]
    return make_candidate(
        kind,
        NATIVE_IDS[kind],
        access_class=access,
        refereed=draw(st.sampled_from([True, False, None])),
        generated=generated,
        declared_authority=declared,
        pids=pids,
    )


@given(candidates())
def test_guard_published_only_with_public_identity_and_never_b_or_c(
    candidate: KnowledgeCandidate,
) -> None:
    suggestion = suggest_authority(candidate)
    assert suggestion.authority in (A, D, E)
    if suggestion.authority is A:
        assert candidate.kind in (ProviderKind.INSPIRE, ProviderKind.LOCAL)
        assert candidate.access_class is AccessClass.PUBLIC
        assert not candidate.facts.generated
        assert any(pid.scheme in PUBLISHED_PID_SCHEMES for pid in candidate.identity_pids)
    if candidate.facts.generated:
        assert suggestion.authority is E
