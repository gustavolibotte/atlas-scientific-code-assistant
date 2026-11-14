"""Authority suggestion policy ``asca-authority/1``.

The suggestion is derived per candidate from what the provider asserts; a provider can
never inject it. Only A (published), D (working material) and E (automated inference) are
ever suggested. A human may choose differently when registering, with a written basis.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from asca.application.knowledge.models import (
    CandidatePid,
    KnowledgeCandidate,
    PidOrigin,
    PidRole,
    ProviderKind,
)
from asca.application.knowledge.pids import HEPDATA_DOI_PREFIX, pid_sort_key, pid_text
from asca.application.knowledge.text import ELLIPSIS, is_line
from asca.domain.provenance import (
    PUBLISHED_PID_SCHEMES,
    AccessClass,
    PersistentIdentifier,
    PidScheme,
    SourceAuthority,
)

AUTHORITY_POLICY_VERSION: Final = "asca-authority/1"
BASIS_MAX: Final = 300
SUGGESTED_AUTHORITIES: Final = frozenset(
    {
        SourceAuthority.PUBLISHED,
        SourceAuthority.WORKING_MATERIAL,
        SourceAuthority.AUTOMATED_INFERENCE,
    }
)


class AuthorityRule(StrEnum):
    INSPIRE_REFEREED = "inspire.refereed/1"
    INSPIRE_OTHER = "inspire.other/1"
    ARXIV_PREPRINT = "arxiv.preprint/1"
    HEPDATA_DATASET = "hepdata.dataset/1"
    LOCAL_DECLARED = "local.declared/1"
    LOCAL_DOWNGRADED = "local.downgraded/1"
    MCP_DOCUMENT = "mcp.document/1"
    MCP_GENERATED = "mcp.generated/1"


@dataclass(frozen=True, slots=True)
class AuthoritySuggestion:
    authority: SourceAuthority
    rule: AuthorityRule
    basis: str
    """A fixed per-rule sentence carrying PIDs only."""

    def __post_init__(self) -> None:
        if self.authority not in SUGGESTED_AUTHORITIES:
            raise ValueError("suggestion.authority must be A, D or E")
        if not isinstance(self.rule, AuthorityRule):
            raise ValueError("suggestion.rule must be an AuthorityRule")
        basis = self.basis
        if not isinstance(basis, str) or not is_line(basis) or len(basis) > BASIS_MAX:
            raise ValueError("suggestion.basis must be a clean line of at most 300 characters")


def _suggest(authority: SourceAuthority, rule: AuthorityRule, basis: str) -> AuthoritySuggestion:
    if len(basis) > BASIS_MAX:
        basis = basis[: BASIS_MAX - 1] + ELLIPSIS
    return AuthoritySuggestion(authority, rule, basis)


def _identity(candidate: KnowledgeCandidate, scheme: PidScheme) -> list[CandidatePid]:
    return [
        item
        for item in candidate.pids
        if item.role is PidRole.IDENTITY and item.pid.scheme is scheme
    ]


def _first_identity_value(candidate: KnowledgeCandidate, scheme: PidScheme) -> str:
    found = _identity(candidate, scheme)
    return found[0].pid.value if found else candidate.ref.native_id


def _inspire(candidate: KnowledgeCandidate) -> AuthoritySuggestion:
    recid = _first_identity_value(candidate, PidScheme.INSPIRE)
    curated = sorted(
        (
            item.pid
            for item in _identity(candidate, PidScheme.DOI)
            if item.origin is PidOrigin.CURATED_LINK
            and not item.pid.value.startswith(HEPDATA_DOI_PREFIX)
        ),
        key=pid_sort_key,
    )
    if (
        candidate.facts.refereed is True
        and curated
        and candidate.access_class is AccessClass.PUBLIC
    ):
        return _suggest(
            SourceAuthority.PUBLISHED,
            AuthorityRule.INSPIRE_REFEREED,
            f"Refereed INSPIRE record {recid} lists DOI {curated[0].value}.",
        )
    return _suggest(
        SourceAuthority.WORKING_MATERIAL,
        AuthorityRule.INSPIRE_OTHER,
        f"INSPIRE record {recid} is not marked refereed with a DOI.",
    )


def _arxiv(candidate: KnowledgeCandidate) -> AuthoritySuggestion:
    basis = f"arXiv preprint {candidate.version.label.removeprefix('arXiv:')}."
    dois = sorted((item.pid for item in _identity(candidate, PidScheme.DOI)), key=pid_sort_key)
    if dois:
        basis += f" Author-supplied DOI {dois[0].value}."
    return _suggest(SourceAuthority.WORKING_MATERIAL, AuthorityRule.ARXIV_PREPRINT, basis)


def _published_identity(candidate: KnowledgeCandidate) -> PersistentIdentifier | None:
    eligible = [pid for pid in candidate.identity_pids if pid.scheme in PUBLISHED_PID_SCHEMES]
    return min(eligible, key=pid_sort_key) if eligible else None


def _local(candidate: KnowledgeCandidate) -> AuthoritySuggestion:
    path = candidate.ref.native_id
    declared = candidate.declared_authority
    if declared is SourceAuthority.PUBLISHED:
        pid = _published_identity(candidate)
        if candidate.access_class is AccessClass.PUBLIC and pid is not None:
            return _suggest(
                SourceAuthority.PUBLISHED,
                AuthorityRule.LOCAL_DECLARED,
                f"Local library document {path} is declared published with {pid_text(pid)}.",
            )
        return _suggest(
            SourceAuthority.WORKING_MATERIAL,
            AuthorityRule.LOCAL_DOWNGRADED,
            f"Local library document {path} is declared published without a public "
            "persistent identifier.",
        )
    if declared is SourceAuthority.AUTOMATED_INFERENCE:
        return _suggest(
            SourceAuthority.AUTOMATED_INFERENCE,
            AuthorityRule.LOCAL_DECLARED,
            f"Local library document {path} is declared automated inference.",
        )
    return _suggest(
        SourceAuthority.WORKING_MATERIAL,
        AuthorityRule.LOCAL_DECLARED,
        f"Local library document {path} is declared working material.",
    )


def suggest_authority(candidate: KnowledgeCandidate) -> AuthoritySuggestion:
    """Deterministic, first match wins, evaluated per candidate (never per group)."""
    if candidate.facts.generated:
        return _suggest(
            SourceAuthority.AUTOMATED_INFERENCE,
            AuthorityRule.MCP_GENERATED,
            "Model-generated answer from an MCP tool.",
        )
    if candidate.kind is ProviderKind.INSPIRE:
        return _inspire(candidate)
    if candidate.kind is ProviderKind.ARXIV:
        return _arxiv(candidate)
    if candidate.kind is ProviderKind.HEPDATA:
        concept = _first_identity_value(candidate, PidScheme.DOI)
        return _suggest(
            SourceAuthority.WORKING_MATERIAL,
            AuthorityRule.HEPDATA_DATASET,
            f"HEPData record {concept}.",
        )
    if candidate.kind is ProviderKind.LOCAL:
        return _local(candidate)
    authority = candidate.declared_authority or SourceAuthority.WORKING_MATERIAL
    return _suggest(
        authority,
        AuthorityRule.MCP_DOCUMENT,
        f"Document from MCP provider {candidate.ref.provider_id}.",
    )
