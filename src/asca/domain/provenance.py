"""Immutable, framework-agnostic provenance domain types."""

from dataclasses import dataclass
from enum import StrEnum


class EvidenceAuthority(StrEnum):
    """Source class, not an endorsement by any scientific collaboration."""

    PUBLISHED = "published"
    DOCUMENTED = "documented"
    IMPLEMENTATION = "implementation"
    UNVERIFIED = "unverified"


class VerificationState(StrEnum):
    """Recorded scientific verification status."""

    NOT_RUN = "not_run"
    PASSED = "passed"
    FAILED = "failed"
    HUMAN_REVIEW_REQUIRED = "human_review_required"


def _require_nonblank(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    id: str
    title: str
    locator: str
    authority: EvidenceAuthority
    is_real_source: bool

    def __post_init__(self) -> None:
        for field in ("id", "title", "locator"):
            _require_nonblank(field, getattr(self, field))
        if self.authority is EvidenceAuthority.PUBLISHED and not self.is_real_source:
            raise ValueError("A synthetic source cannot be classified as published")


@dataclass(frozen=True, slots=True)
class CodeSymbol:
    id: str
    qualified_name: str
    file_path: str
    revision: str

    def __post_init__(self) -> None:
        for field in ("id", "qualified_name", "file_path", "revision"):
            _require_nonblank(field, getattr(self, field))
        if self.file_path.startswith("/") or ".." in self.file_path.split("/"):
            raise ValueError("Code symbol path must be workspace-relative")


@dataclass(frozen=True, slots=True)
class VerificationRecord:
    id: str
    label: str
    state: VerificationState

    def __post_init__(self) -> None:
        _require_nonblank("id", self.id)
        _require_nonblank("label", self.label)


@dataclass(frozen=True, slots=True)
class ScientificDecision:
    id: str
    statement: str
    rationale: str
    evidence_ids: tuple[str, ...]
    code_symbol_ids: tuple[str, ...]
    verification_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        for field in ("id", "statement", "rationale"):
            _require_nonblank(field, getattr(self, field))
        for key in ("evidence_ids", "code_symbol_ids", "verification_ids"):
            values: tuple[str, ...] = getattr(self, key)
            if len(set(values)) != len(values):
                raise ValueError(f"Duplicate identifiers in {key}")
            for value in values:
                _require_nonblank(key, value)


@dataclass(frozen=True, slots=True)
class ProvenanceTrace:
    """A versioned decision trace whose references must all resolve."""

    decision: ScientificDecision
    evidence: tuple[EvidenceReference, ...]
    symbols: tuple[CodeSymbol, ...]
    verifications: tuple[VerificationRecord, ...]
    is_synthetic: bool

    def __post_init__(self) -> None:
        for collection, referenced, name in (
            (self.evidence, self.decision.evidence_ids, "evidence"),
            (self.symbols, self.decision.code_symbol_ids, "symbols"),
            (self.verifications, self.decision.verification_ids, "verifications"),
        ):
            ids = [item.id for item in collection]
            if len(ids) != len(set(ids)):
                raise ValueError(f"Duplicate entries in {name}")
            if set(referenced) != set(ids):
                raise ValueError(f"Broken {name} relation in provenance trace")
        if self.is_synthetic and any(source.is_real_source for source in self.evidence):
            raise ValueError("A fully synthetic trace must not claim real evidence")
