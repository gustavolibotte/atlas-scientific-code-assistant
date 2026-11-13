"""Handwritten, released v1 JSON Schemas for the export documents."""

import copy
import hashlib
from collections.abc import Iterator
from enum import StrEnum
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from jsonschema import Draft202012Validator, FormatChecker
from provenance_builders import build_complete_real_project, make_service
from provenance_strategies import valid_graphs

from asca import contracts
from asca.application.demo import DEMO_PROJECT_ID, seed_synthetic_demo
from asca.application.exports import ExportArtifact, WithheldKind, build_export
from asca.contracts import (
    EXPORT_ARTIFACT_NAMES,
    EXPORT_SCHEMA_VERSION,
    export_schema_resource,
    load_export_schema,
    released_schema_hashes,
    schema_id,
)
from asca.domain.provenance import (
    AccessClass,
    ApprovalVerdict,
    AssertionOrigin,
    CheckMethod,
    ClaimCheckOutcome,
    ClaimVerificationState,
    Currency,
    DecisionStatus,
    LinkFreshness,
    LocatorKind,
    PidScheme,
    ProvenanceGraph,
    RunOrigin,
    SourceAuthority,
    Stance,
    StatusReason,
    SupersessionDimension,
    TestKind,
    TestOutcome,
)
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository

pytestmark = pytest.mark.contract

ENUM_DEFS: dict[str, type[StrEnum]] = {
    "access_class": AccessClass,
    "withheld_kind": WithheldKind,
    "pid_scheme": PidScheme,
    "source_authority": SourceAuthority,
    "currency": Currency,
    "supersession_dimension": SupersessionDimension,
    "locator_kind": LocatorKind,
    "assertion_origin": AssertionOrigin,
    "claim_verification_state": ClaimVerificationState,
    "claim_check_outcome": ClaimCheckOutcome,
    "check_method": CheckMethod,
    "decision_status": DecisionStatus,
    "status_reason": StatusReason,
    "stance": Stance,
    "approval_verdict": ApprovalVerdict,
    "link_freshness": LinkFreshness,
    "test_kind": TestKind,
    "test_outcome": TestOutcome,
    "run_origin": RunOrigin,
}
PREDICATE_KEYWORDS = ("if", "then", "else", "contains", "not")


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(load_export_schema(name), format_checker=FormatChecker())


VALIDATORS = {name: _validator(name) for name in EXPORT_ARTIFACT_NAMES}


def _walk(node: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    yield path, node
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _walk(value, (*path, str(key)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, (*path, str(index)))


def _demo_graph() -> ProvenanceGraph:
    repo = InMemoryProvenanceRepository()
    seed_synthetic_demo(repo)
    return repo.load(DEMO_PROJECT_ID)


def _complete_graph() -> ProvenanceGraph:
    service = make_service()
    return service.load(build_complete_real_project(service).project)


def _export(graph: ProvenanceGraph, artifact: ExportArtifact, audience: AccessClass) -> Any:
    return build_export(graph, artifact, audience=audience, generator_version="0.0.0-test")


def _assert_valid(graph: ProvenanceGraph) -> None:
    for artifact in ExportArtifact:
        for audience in AccessClass:
            errors = list(
                VALIDATORS[artifact.value].iter_errors(_export(graph, artifact, audience))
            )
            assert errors == [], (artifact, audience, errors[0].message)


def _errors(artifact: ExportArtifact, document: Any) -> list[str]:
    return [error.message for error in VALIDATORS[artifact.value].iter_errors(document)]


# ---------------------------------------------------------------------- schema files


def test_the_three_artifacts_are_named_consistently() -> None:
    assert tuple(item.value for item in ExportArtifact) == EXPORT_ARTIFACT_NAMES
    assert EXPORT_SCHEMA_VERSION == "1.0.0"


@pytest.mark.parametrize("name", EXPORT_ARTIFACT_NAMES)
def test_schema_is_a_valid_draft_2020_12_schema_with_its_urn(name: str) -> None:
    schema = load_export_schema(name)
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == schema_id(name) == f"urn:asca:schema:{name}:v1"
    properties: Any = schema["properties"]
    assert properties["schema"] == {"const": schema_id(name)}
    assert properties["schema_version"] == {"const": EXPORT_SCHEMA_VERSION}


@pytest.mark.parametrize("name", EXPORT_ARTIFACT_NAMES)
def test_schema_file_hash_matches_the_released_lock(name: str) -> None:
    released = released_schema_hashes()
    assert set(released) == {f"{item}.v1" for item in EXPORT_ARTIFACT_NAMES}
    digest = hashlib.sha256(export_schema_resource(name).read_bytes()).hexdigest()
    assert digest == released[f"{name}.v1"]


def test_unknown_schema_names_are_rejected() -> None:
    for name in ("secret", "../released", "evidence_manifest.schema"):
        with pytest.raises(ValueError):
            load_export_schema(name)


@pytest.mark.parametrize("name", EXPORT_ARTIFACT_NAMES)
def test_every_enum_lives_in_defs_and_equals_its_str_enum(name: str) -> None:
    schema = load_export_schema(name)
    defs: Any = schema["$defs"]
    for path, node in _walk(schema):
        if isinstance(node, dict) and "enum" in node:
            assert len(path) == 2 and path[0] == "$defs", path
    enum_defs = {key: value["enum"] for key, value in defs.items() if "enum" in value}
    assert enum_defs, name
    for key, values in enum_defs.items():
        if key == "authority_letter":
            assert values == [item.letter for item in SourceAuthority]
        else:
            assert values == [item.value for item in ENUM_DEFS[key]], key


@pytest.mark.parametrize("name", EXPORT_ARTIFACT_NAMES)
def test_every_object_level_forbids_additional_properties(name: str) -> None:
    for path, node in _walk(load_export_schema(name)):
        if any(keyword in path for keyword in PREDICATE_KEYWORDS):
            continue
        if isinstance(node, dict) and ("properties" in node or node.get("type") == "object"):
            assert node.get("additionalProperties") is False, path


@pytest.mark.parametrize("name", EXPORT_ARTIFACT_NAMES)
def test_shared_defs_are_repeated_in_every_file(name: str) -> None:
    defs: Any = load_export_schema(name)["$defs"]
    assert defs["id"]["pattern"] == "^[a-z]{3}_[0-9a-f]{32}$"
    assert defs["sha256"]["pattern"] == "^[0-9a-f]{64}$"
    assert defs["utc"]["pattern"] == r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
    assert defs["date"]["pattern"] == r"^\d{4}-\d{2}-\d{2}$"


# ---------------------------------------------------------------------- exports validate


def test_demo_and_complete_project_exports_validate_for_every_audience() -> None:
    _assert_valid(_demo_graph())
    _assert_valid(_complete_graph())


@settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(graph=valid_graphs())
def test_exports_of_valid_graphs_validate_for_every_audience(graph: ProvenanceGraph) -> None:
    _assert_valid(graph)


# ---------------------------------------------------------------------- negative cases


def _decision(document: Any, status: str) -> Any:
    return next(item for item in document["decisions"] if item["status"] == status)


def test_approved_decision_without_reviews_is_rejected() -> None:
    document = _export(_complete_graph(), ExportArtifact.DECISION_RECORDS, AccessClass.RESTRICTED)
    assert _errors(ExportArtifact.DECISION_RECORDS, document) == []
    _decision(document, "approved")["reviews"] = []
    assert _errors(ExportArtifact.DECISION_RECORDS, document) != []


def test_stale_approved_decision_is_rejected() -> None:
    document = _export(_complete_graph(), ExportArtifact.DECISION_RECORDS, AccessClass.RESTRICTED)
    _decision(document, "approved")["approval_stale"] = True
    assert _errors(ExportArtifact.DECISION_RECORDS, document) != []


@pytest.mark.parametrize(
    "mutation",
    [
        {"claim_state": "not_checked"},
        {"stance": "context"},
        {"authority": "automated_inference"},
    ],
)
def test_supported_decision_without_a_checked_support_item_is_rejected(
    mutation: dict[str, str],
) -> None:
    document = _export(_demo_graph(), ExportArtifact.DECISION_RECORDS, AccessClass.PUBLIC)
    assert _errors(ExportArtifact.DECISION_RECORDS, document) == []
    decision = _decision(document, "supported")
    assert len(decision["evidence"]) == 1
    decision["evidence"][0].update(mutation)
    assert _errors(ExportArtifact.DECISION_RECORDS, document) != []
    decision["evidence"] = []
    assert _errors(ExportArtifact.DECISION_RECORDS, document) != []


@pytest.mark.parametrize("artifact", list(ExportArtifact))
def test_extra_properties_are_rejected_at_every_level(artifact: ExportArtifact) -> None:
    document = _export(_complete_graph(), artifact, AccessClass.RESTRICTED)
    top = copy.deepcopy(document)
    top["extra"] = 1
    assert _errors(artifact, top) != []
    project = copy.deepcopy(document)
    project["project"]["extra"] = 1
    assert _errors(artifact, project) != []
    nested = copy.deepcopy(document)
    collection = {
        ExportArtifact.EVIDENCE_MANIFEST: "claims",
        ExportArtifact.DECISION_RECORDS: "decisions",
        ExportArtifact.VALIDATION_REPORT: "runs",
    }[artifact]
    nested[collection][0]["extra"] = 1
    assert _errors(artifact, nested) != []


@pytest.mark.parametrize("artifact", list(ExportArtifact))
def test_wrong_envelope_values_are_rejected(artifact: ExportArtifact) -> None:
    document = _export(_demo_graph(), artifact, AccessClass.PUBLIC)
    for key, value in (
        ("schema_version", "1.0.1"),
        ("schema", "urn:asca:schema:other:v1"),
        ("policy_note", "An official ATLAS classification."),
        ("synthetic_notice", None),
        ("audience", "secret"),
    ):
        mutated = copy.deepcopy(document)
        mutated[key] = value
        assert _errors(artifact, mutated) != [], key
    real = _export(_complete_graph(), artifact, AccessClass.PUBLIC)
    real["synthetic_notice"] = document["synthetic_notice"]
    assert _errors(artifact, real) != []


def test_withheld_public_entries_and_non_utc_times_are_rejected() -> None:
    document = _export(_demo_graph(), ExportArtifact.EVIDENCE_MANIFEST, AccessClass.PUBLIC)
    public = copy.deepcopy(document)
    public["withheld"][0]["access_class"] = "public"
    assert _errors(ExportArtifact.EVIDENCE_MANIFEST, public) != []
    decision = copy.deepcopy(document)
    decision["withheld"][0]["kind"] = "decision"
    assert _errors(ExportArtifact.EVIDENCE_MANIFEST, decision) != []
    offset = copy.deepcopy(document)
    offset["claims"][0]["recorded_at"] = "2026-11-12T00:00:00+00:00"
    assert _errors(ExportArtifact.EVIDENCE_MANIFEST, offset) != []
    report = _export(_demo_graph(), ExportArtifact.VALIDATION_REPORT, AccessClass.PUBLIC)
    report["withheld"] = copy.deepcopy(document["withheld"][:1])
    assert _errors(ExportArtifact.VALIDATION_REPORT, report) != []


def test_malformed_packaged_contract_files_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "v1").mkdir()
    (tmp_path / "v1" / "evidence_manifest.schema.json").write_text("[]", encoding="utf-8")
    (tmp_path / "released.json").write_text('{"evidence_manifest.v1": 1}', encoding="utf-8")
    monkeypatch.setattr(contracts, "_exports_dir", lambda: tmp_path)
    with pytest.raises(ValueError):
        load_export_schema("evidence_manifest")
    with pytest.raises(ValueError):
        released_schema_hashes()
