"""Versioned transport models, independent from domain entities."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from asca.domain.provenance import EvidenceAuthority, VerificationState


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
