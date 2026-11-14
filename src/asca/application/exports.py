"""Reproducible, audience-filtered export documents.

Every builder is a pure function of ``(graph, artifact, audience, generator_version)``:
no clock, no I/O and no timestamp in the document, so the same inputs always give the
same bytes from :func:`canonical_json`. Records the audience may not see are withheld
whole and listed in ``withheld``; their text never appears in the document.
"""

import json
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, date, datetime
from enum import StrEnum

from asca.contracts import EXPORT_SCHEMA_VERSION, schema_id
from asca.domain.provenance import (
    POLICY_NOTE,
    QUOTE_NORMALIZATION_VERSION,
    SYNTHETIC_NOTICE,
    AccessClass,
    Approval,
    Claim,
    CodeSymbol,
    EnvironmentSnapshot,
    ProvenanceGraph,
    RunOrigin,
    ScientificDecision,
    Source,
    SourceVersion,
    SupersessionDimension,
    SymbolLineage,
    TestCase,
    TestOutcome,
    ValidationRun,
    WorkspaceRevision,
    currency,
    derive_status,
    latest_result,
)

GENERATOR_NAME = "asca"
NOT_RUN = "not_run"

Document = dict[str, object]


class ExportArtifact(StrEnum):
    EVIDENCE_MANIFEST = "evidence_manifest"
    DECISION_RECORDS = "decision_records"
    VALIDATION_REPORT = "validation_report"


class WithheldKind(StrEnum):
    """Kinds of records an export can withhold from its audience."""

    SOURCE = "source"
    SOURCE_VERSION = "source_version"
    CLAIM = "claim"
    DECISION = "decision"
    TEST_CASE = "test_case"


WITHHELD_SUPERSESSION_REASON = (
    "Reason withheld: the superseding version is not available to this audience."
)


def format_utc(value: datetime) -> str:
    """Format an aware datetime as ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` in UTC."""
    moment = value.astimezone(UTC)
    return (
        f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}T"
        f"{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}."
        f"{moment.microsecond:06d}Z"
    )


def _optional_utc(value: datetime | None) -> str | None:
    return None if value is None else format_utc(value)


def _optional_date(value: date | None) -> str | None:
    return None if value is None else value.isoformat()


def canonical_json(document: Mapping[str, object]) -> bytes:
    """Byte-reproducible JSON: sorted keys, two-space indent, UTF-8, trailing newline."""
    text = json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
    return (text + "\n").encode("utf-8")


# ---------------------------------------------------------------------- envelope


def _withheld(kind: WithheldKind, record_id: str, access_class: AccessClass) -> Document:
    return {"kind": kind.value, "id": record_id, "access_class": access_class.value}


def _envelope(
    graph: ProvenanceGraph,
    artifact: ExportArtifact,
    audience: AccessClass,
    generator_version: str,
    withheld: Iterable[Document],
) -> Document:
    project = graph.project
    return {
        "schema": schema_id(artifact.value),
        "schema_version": EXPORT_SCHEMA_VERSION,
        "generator": {"name": GENERATOR_NAME, "version": generator_version},
        "project": {
            "id": project.id,
            "title": project.title,
            "is_synthetic": project.is_synthetic,
            "revision": graph.revision,
        },
        "audience": audience.value,
        "policy_note": POLICY_NOTE,
        "synthetic_notice": SYNTHETIC_NOTICE if project.is_synthetic else None,
        "withheld": sorted(withheld, key=lambda item: (str(item["kind"]), str(item["id"]))),
    }


# ---------------------------------------------------------------------- evidence manifest


def _notice_reason(
    graph: ProvenanceGraph,
    superseding_version_id: str | None,
    reason: str,
    audience: AccessClass,
) -> str:
    """Free text about a superseding version follows that version's access class."""
    if superseding_version_id is None:
        return reason
    superseding = graph.get(SourceVersion, superseding_version_id)
    return reason if audience.permits(superseding.access_class) else WITHHELD_SUPERSESSION_REASON


def _least_restrictive(classes: Iterable[AccessClass]) -> AccessClass:
    return min(classes, key=lambda item: item.rank, default=AccessClass.PUBLIC)


def _version_document(
    graph: ProvenanceGraph, version: SourceVersion, audience: AccessClass
) -> Document:
    notices = sorted(graph.notices_for(version.id), key=lambda item: (item.recorded_at, item.id))
    return {
        "id": version.id,
        "version_label": version.version_label,
        "authority": version.authority.value,
        "authority_letter": version.authority.letter,
        "access_class": version.access_class.value,
        "access_conditions": version.access_conditions,
        "authority_basis": version.authority_basis,
        "content_sha256": version.content_sha256,
        "retrieved_at": _optional_utc(version.retrieved_at),
        "published_on": _optional_date(version.published_on),
        "recorded_at": format_utc(version.recorded_at),
        "currency": {
            "scientific": currency(graph, version.id, SupersessionDimension.SCIENTIFIC).value,
            "technical": currency(graph, version.id, SupersessionDimension.TECHNICAL).value,
        },
        "superseded_by": [
            {
                "dimension": notice.dimension.value,
                "version_id": notice.superseding_version_id,
                "reason": _notice_reason(
                    graph, notice.superseding_version_id, notice.reason, audience
                ),
                "recorded_at": format_utc(notice.recorded_at),
            }
            for notice in notices
        ],
    }


def _source_document(
    graph: ProvenanceGraph,
    source: Source,
    versions: Iterable[SourceVersion],
    audience: AccessClass,
) -> Document:
    ordered = sorted(versions, key=lambda item: (item.recorded_at, item.id))
    return {
        "id": source.id,
        "title": source.title,
        "persistent_id": {
            "scheme": source.persistent_id.scheme.value,
            "value": source.persistent_id.value,
        },
        "is_synthetic": source.is_synthetic,
        "versions": [_version_document(graph, version, audience) for version in ordered],
    }


def _claim_document(graph: ProvenanceGraph, claim: Claim) -> Document:
    return {
        "id": claim.id,
        "source_version_id": claim.source_version_id,
        "quote": claim.quote,
        "locator": [{"kind": part.kind.value, "value": part.value} for part in claim.locator.parts],
        "statement": claim.statement,
        "extracted_by": claim.extracted_by.value,
        "recorded_at": format_utc(claim.recorded_at),
        "verification": {
            "state": graph.claim_state(claim.id).value,
            "normalization_version": QUOTE_NORMALIZATION_VERSION,
            "checks": [
                {
                    "sequence": check.sequence,
                    "outcome": check.outcome.value,
                    "method": check.method.value,
                    "content_sha256": check.content_sha256,
                    "detail": check.detail,
                    "checked_at": format_utc(check.checked_at),
                }
                for check in graph.checks_for(claim.id)
            ],
        },
    }


def _evidence_manifest(
    graph: ProvenanceGraph, audience: AccessClass
) -> tuple[Document, list[Document]]:
    withheld: list[Document] = []
    sources: list[Document] = []
    for source in graph.sources:
        versions = [item for item in graph.versions if item.source_id == source.id]
        permitted = [item for item in versions if audience.permits(item.access_class)]
        withheld.extend(
            _withheld(WithheldKind.SOURCE_VERSION, item.id, item.access_class)
            for item in versions
            if not audience.permits(item.access_class)
        )
        source_class = _least_restrictive(item.access_class for item in versions)
        if not audience.permits(source_class):
            withheld.append(_withheld(WithheldKind.SOURCE, source.id, source_class))
            continue
        sources.append(_source_document(graph, source, permitted, audience))
    claims: list[Document] = []
    for claim in sorted(graph.claims, key=lambda item: (item.recorded_at, item.id)):
        version = graph.get(SourceVersion, claim.source_version_id)
        if not audience.permits(version.access_class):
            withheld.append(_withheld(WithheldKind.CLAIM, claim.id, version.access_class))
            continue
        claims.append(_claim_document(graph, claim))
    return {"sources": sources, "claims": claims}, withheld


# ---------------------------------------------------------------------- decision records


def _review_document(approval: Approval, current_id: str | None) -> Document:
    return {
        "id": approval.id,
        "sequence": approval.sequence,
        "verdict": approval.verdict.value,
        "reviewer": approval.reviewer,
        "rationale": approval.rationale,
        "conflict_resolution": approval.conflict_resolution,
        "support_fingerprint": approval.support_fingerprint,
        "reviewed_at": format_utc(approval.reviewed_at),
        "is_current": approval.id == current_id,
    }


def _decision_document(
    graph: ProvenanceGraph, lineage: SymbolLineage, decision: ScientificDecision
) -> Document:
    report = derive_status(graph, decision.id)
    evidence: list[Document] = []
    for link in sorted(graph.links_for(decision.id), key=lambda item: (item.created_at, item.id)):
        claim = graph.get(Claim, link.claim_id)
        version = graph.get(SourceVersion, claim.source_version_id)
        evidence.append(
            {
                "link_id": link.id,
                "claim_id": link.claim_id,
                "stance": link.stance.value,
                "asserted_by": link.asserted_by.value,
                "note": link.note,
                "claim_state": graph.claim_state(link.claim_id).value,
                "authority": version.authority.value,
                "created_at": format_utc(link.created_at),
            }
        )
    implemented_by: list[Document] = []
    for impl in sorted(
        graph.implementation_links_for_decision(decision.id),
        key=lambda item: (item.created_at, item.id),
    ):
        symbol = graph.get(CodeSymbol, impl.symbol_id)
        implemented_by.append(
            {
                "link_id": impl.id,
                "symbol_id": symbol.id,
                "qualified_name": symbol.qualified_name,
                "file_path": symbol.file_path,
                "revision_sequence": graph.get(WorkspaceRevision, symbol.revision_id).sequence,
                "fingerprint": symbol.fingerprint,
                "freshness": lineage.resolve(impl).freshness.value,
                "created_at": format_utc(impl.created_at),
            }
        )
    verified_by = [
        {"link_id": link.id, "test_case_id": link.test_case_id}
        for link in sorted(
            graph.verification_links_for_decision(decision.id),
            key=lambda item: (item.created_at, item.id),
        )
    ]
    return {
        "id": decision.id,
        "title": decision.title,
        "statement": decision.statement,
        "rationale": decision.rationale,
        "alternatives": [
            {
                "label": item.label,
                "description": item.description,
                "reason_not_chosen": item.reason_not_chosen,
            }
            for item in decision.alternatives
        ],
        "assumptions": [
            {"statement": item.statement, "justification": item.justification}
            for item in decision.assumptions
        ],
        "access_floor": decision.access_floor.value,
        "effective_access_class": report.effective_access_class.value,
        "status": report.status.value,
        "evidential_status": report.evidential_status.value,
        "status_reasons": [reason.value for reason in report.reasons],
        "approval_stale": report.approval_stale,
        "support_fingerprint": report.support_fingerprint,
        "supersedes": decision.supersedes_id,
        "superseded_by": report.superseded_by,
        "created_at": format_utc(decision.created_at),
        "evidence": evidence,
        "implemented_by": implemented_by,
        "verified_by": verified_by,
        "reviews": [
            _review_document(approval, report.current_approval_id)
            for approval in graph.approvals_for(decision.id)
        ],
    }


def _decision_records(
    graph: ProvenanceGraph, audience: AccessClass
) -> tuple[Document, list[Document]]:
    withheld: list[Document] = []
    decisions: list[Document] = []
    lineage = SymbolLineage(graph)
    for decision in sorted(graph.decisions, key=lambda item: (item.created_at, item.id)):
        access_class = derive_status(graph, decision.id).effective_access_class
        if not audience.permits(access_class):
            withheld.append(_withheld(WithheldKind.DECISION, decision.id, access_class))
            continue
        decisions.append(_decision_document(graph, lineage, decision))
    return {"decisions": decisions}, withheld


# ---------------------------------------------------------------------- validation report


def _outcome_counts(outcomes: Iterable[TestOutcome]) -> dict[str, int]:
    counts = {outcome.value: 0 for outcome in TestOutcome}
    for outcome in outcomes:
        counts[outcome.value] += 1
    return counts


def _environment_document(environment: EnvironmentSnapshot) -> Document:
    return {
        "id": environment.id,
        "python_version": environment.python_version,
        "implementation": environment.implementation,
        "platform": environment.platform,
        "packages": [{"name": pin.name, "version": pin.version} for pin in environment.packages],
    }


def _test_case_access_class(graph: ProvenanceGraph, test: TestCase) -> AccessClass:
    """A test inherits the most restrictive class of the decisions it verifies."""
    classes = [
        derive_status(graph, link.decision_id).effective_access_class
        for link in graph.verification_links
        if link.test_case_id == test.id and link.decision_id is not None
    ]
    return max(classes, key=lambda item: item.rank, default=AccessClass.PUBLIC)


def _latest_outcome_key(graph: ProvenanceGraph, test: TestCase) -> str:
    """A synthetic run is not an execution, so its test counts as not run."""
    latest = latest_result(graph, test.id)
    if latest is None or latest[0].origin is RunOrigin.SYNTHETIC:
        return NOT_RUN
    return latest[1].outcome.value


def _test_case_document(graph: ProvenanceGraph, test: TestCase) -> Document:
    links = [link for link in graph.verification_links if link.test_case_id == test.id]
    latest = latest_result(graph, test.id)
    return {
        "id": test.id,
        "node_id": test.node_id,
        "kind": test.kind.value,
        "description": test.description,
        "created_at": format_utc(test.created_at),
        "verifies": {
            "decision_ids": sorted(
                link.decision_id for link in links if link.decision_id is not None
            ),
            "symbol_ids": sorted(link.symbol_id for link in links if link.symbol_id is not None),
        },
        "latest": (
            None
            if latest is None
            else {
                "run_id": latest[0].id,
                "outcome": latest[1].outcome.value,
                "origin": latest[0].origin.value,
            }
        ),
    }


def _run_document(graph: ProvenanceGraph, run: ValidationRun, hidden: frozenset[str]) -> Document:
    revision = graph.get(WorkspaceRevision, run.revision_id)
    results = [result for result in run.results if result.test_case_id not in hidden]
    return {
        "id": run.id,
        "origin": run.origin.value,
        "revision_id": revision.id,
        "revision_sequence": revision.sequence,
        "vcs_ref": revision.vcs_ref,
        "environment_id": run.environment_id,
        "started_at": format_utc(run.started_at),
        "finished_at": format_utc(run.finished_at),
        "summary": _outcome_counts(result.outcome for result in results),
        "results": [
            {
                "test_case_id": result.test_case_id,
                "outcome": result.outcome.value,
                "duration_seconds": result.duration_seconds,
                "message": result.message,
            }
            for result in results
        ],
    }


def _validation_report(
    graph: ProvenanceGraph, audience: AccessClass
) -> tuple[Document, list[Document]]:
    withheld: list[Document] = []
    tests: list[TestCase] = []
    for test in sorted(graph.test_cases, key=lambda item: item.node_id):
        access_class = _test_case_access_class(graph, test)
        if audience.permits(access_class):
            tests.append(test)
        else:
            withheld.append(_withheld(WithheldKind.TEST_CASE, test.id, access_class))
    hidden = frozenset(str(item["id"]) for item in withheld)
    latest_outcomes: dict[str, int] = {**_outcome_counts(()), NOT_RUN: 0}
    for test in tests:
        latest_outcomes[_latest_outcome_key(graph, test)] += 1
    body: Document = {
        "environments": [_environment_document(item) for item in graph.environments],
        "test_cases": [_test_case_document(graph, test) for test in tests],
        "runs": [
            _run_document(graph, run, hidden)
            for run in sorted(graph.runs, key=lambda item: (item.finished_at, item.id))
        ],
        "summary": {
            "test_case_count": len(tests),
            "run_count": len(graph.runs),
            "latest_outcomes": latest_outcomes,
        },
    }
    return body, withheld


_BUILDERS: dict[
    ExportArtifact,
    Callable[[ProvenanceGraph, AccessClass], tuple[Document, list[Document]]],
] = {
    ExportArtifact.EVIDENCE_MANIFEST: _evidence_manifest,
    ExportArtifact.DECISION_RECORDS: _decision_records,
    ExportArtifact.VALIDATION_REPORT: _validation_report,
}


def build_export(
    graph: ProvenanceGraph,
    artifact: ExportArtifact,
    *,
    audience: AccessClass,
    generator_version: str,
) -> dict[str, object]:
    """Build one export document of ``graph`` for ``audience``.

    The output depends only on the arguments. It never carries a generation timestamp:
    ``project.revision`` pins the exact state that was exported.
    """
    if not isinstance(graph, ProvenanceGraph):
        raise TypeError("graph must be a ProvenanceGraph")
    kind = ExportArtifact(artifact)
    viewer = AccessClass(audience)
    if not isinstance(generator_version, str) or generator_version.strip() == "":
        raise ValueError("generator_version must be a non-blank string")
    body, withheld = _BUILDERS[kind](graph, viewer)
    return {**_envelope(graph, kind, viewer, generator_version, withheld), **body}
