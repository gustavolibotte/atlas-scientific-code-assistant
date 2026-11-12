"""Reproducible export documents (implemented by Workstream B; skeleton only)."""

from collections.abc import Mapping
from enum import StrEnum

from asca.domain.provenance import AccessClass, ProvenanceGraph


class ExportArtifact(StrEnum):
    EVIDENCE_MANIFEST = "evidence_manifest"
    DECISION_RECORDS = "decision_records"
    VALIDATION_REPORT = "validation_report"


def build_export(
    graph: ProvenanceGraph,
    artifact: ExportArtifact,
    *,
    audience: AccessClass,
    generator_version: str,
) -> dict[str, object]:
    raise NotImplementedError("exports are not implemented yet")


def canonical_json(document: Mapping[str, object]) -> bytes:
    raise NotImplementedError("exports are not implemented yet")
