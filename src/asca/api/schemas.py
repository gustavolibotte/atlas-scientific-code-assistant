"""Versioned transport models, independent from domain entities."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict


class EvidenceAuthority(StrEnum):
    """Legacy demo-trace source class, kept for the frozen ``/api/v1/demo/trace`` contract."""

    PUBLISHED = "published"
    DOCUMENTED = "documented"
    IMPLEMENTATION = "implementation"
    UNVERIFIED = "unverified"


class VerificationState(StrEnum):
    """Legacy demo-trace verification state, kept for the frozen contract."""

    NOT_RUN = "not_run"
    PASSED = "passed"
    FAILED = "failed"
    HUMAN_REVIEW_REQUIRED = "human_review_required"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LiveResponse(StrictModel):
    status: str


class ReadyResponse(StrictModel):
    status: str
    version: str


class CapabilityState(StrEnum):
    AVAILABLE = "available"
    DEMO_ONLY = "demo_only"
    NOT_IMPLEMENTED = "not_implemented"


class Capability(StrictModel):
    id: str
    label: str
    status: CapabilityState


class CapabilitiesResponse(StrictModel):
    items: list[Capability]


class EvidenceDTO(StrictModel):
    id: str
    title: str
    locator: str
    authority: EvidenceAuthority
    is_real_source: bool


class SymbolDTO(StrictModel):
    id: str
    qualified_name: str
    file_path: str
    revision: str


class VerificationDTO(StrictModel):
    id: str
    label: str
    state: VerificationState


class DecisionDTO(StrictModel):
    id: str
    statement: str
    rationale: str
    evidence_ids: tuple[str, ...]
    code_symbol_ids: tuple[str, ...]
    verification_ids: tuple[str, ...]


class TraceResponse(StrictModel):
    is_synthetic: bool
    disclaimer: str
    decision: DecisionDTO
    evidence: list[EvidenceDTO]
    symbols: list[SymbolDTO]
    verifications: list[VerificationDTO]


class IdentityStatusResponse(StrictModel):
    """Public status only; never exposes OIDC configuration or credentials."""

    provider: Literal["cern"] = "cern"
    status: Literal["not_configured"] = "not_configured"
    authentication_enabled: bool = False
    protocol: Literal["oidc_authorization_code_pkce"] = "oidc_authorization_code_pkce"
    note: str = "OIDC contracts only; login, callbacks and token exchange are disabled."
