"""Reproducible, audience-filtered export documents built from a provenance graph."""

import os
import random
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from provenance_builders import CompleteProject, build_complete_real_project, make_service

from asca.application.demo import (
    DEMO_NAMESPACE,
    DEMO_PROJECT_ID,
    DEMO_TIME,
    deterministic_id,
    seed_synthetic_demo,
)
from asca.application.exports import (
    ExportArtifact,
    WithheldKind,
    build_export,
    canonical_json,
    format_utc,
)
from asca.application.provenance import EnvironmentDraft, RunDraft, SourceDraft, VersionDraft
from asca.domain.provenance import (
    POLICY_NOTE,
    RECORD_FIELDS,
    SYNTHETIC_NOTICE,
    AccessClass,
    CodeSymbol,
    IdKind,
    PersistentIdentifier,
    PidScheme,
    ProvenanceGraph,
    RunOrigin,
    SourceAuthority,
    TestKind,
    TestOutcome,
    TestResult,
)
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository

pytestmark = pytest.mark.unit

GOLDEN_DIR = Path(__file__).parents[1] / "contract" / "golden"
TEST_VERSION = "0.0.0-test"
GOLDEN_CASES = [
    (ExportArtifact.EVIDENCE_MANIFEST, AccessClass.PUBLIC),
    (ExportArtifact.DECISION_RECORDS, AccessClass.PUBLIC),
    (ExportArtifact.VALIDATION_REPORT, AccessClass.PUBLIC),
    (ExportArtifact.EVIDENCE_MANIFEST, AccessClass.INTERNAL),
]


def _demo_graph() -> ProvenanceGraph:
    repo = InMemoryProvenanceRepository()
    seed_synthetic_demo(repo)
    return repo.load(DEMO_PROJECT_ID)


def _complete_graph() -> tuple[ProvenanceGraph, CompleteProject]:
    service = make_service()
    names = build_complete_real_project(service)
    return service.load(names.project), names


def _export(
    graph: ProvenanceGraph, artifact: ExportArtifact, audience: AccessClass
) -> dict[str, Any]:
    return build_export(graph, artifact, audience=audience, generator_version=TEST_VERSION)


def _all(graph: ProvenanceGraph, audience: AccessClass) -> dict[ExportArtifact, dict[str, Any]]:
    return {artifact: _export(graph, artifact, audience) for artifact in ExportArtifact}


def _demo(kind: IdKind, counter: int) -> str:
    return deterministic_id(DEMO_NAMESPACE, kind, counter)


# ---------------------------------------------------------------------- golden files


@pytest.mark.parametrize(("artifact", "audience"), GOLDEN_CASES)
def test_demo_exports_match_the_golden_bytes(
    artifact: ExportArtifact, audience: AccessClass
) -> None:
    golden = GOLDEN_DIR / f"demo_{artifact.value}.{audience.value}.json"
    produced = canonical_json(_export(_demo_graph(), artifact, audience))
    if os.environ.get("ASCA_UPDATE_GOLDENS") == "1":
        golden.write_bytes(produced)
    assert produced == golden.read_bytes()


# ---------------------------------------------------------------------- determinism


def test_same_input_gives_identical_bytes() -> None:
    graph, _ = _complete_graph()
    again, _ = _complete_graph()
    for audience in AccessClass:
        for artifact in ExportArtifact:
            first = canonical_json(_export(graph, artifact, audience))
            assert first == canonical_json(_export(graph, artifact, audience))
            assert first == canonical_json(_export(again, artifact, audience))


@pytest.mark.parametrize("seed", [0, 1, 2, 3])
def test_shuffled_graph_tuples_give_identical_bytes(seed: int) -> None:
    graph, _ = _complete_graph()
    rng = random.Random(seed)
    shuffled: dict[str, tuple[object, ...]] = {}
    for name in RECORD_FIELDS.values():
        items = list(getattr(graph, name))
        rng.shuffle(items)
        shuffled[name] = tuple(items)
    other = replace(graph, **shuffled)  # type: ignore[arg-type]
    for audience in AccessClass:
        for artifact in ExportArtifact:
            assert canonical_json(_export(other, artifact, audience)) == canonical_json(
                _export(graph, artifact, audience)
            )


def test_canonical_json_is_sorted_indented_utf8_with_a_trailing_newline() -> None:
    assert (
        canonical_json({"b": "é", "a": [1, {"d": None, "c": True}]})
        == (
            '{\n  "a": [\n    1,\n    {\n      "c": true,\n      "d": null\n    }\n  ],\n'
            '  "b": "é"\n}\n'
        ).encode()
    )
    with pytest.raises(ValueError):
        canonical_json({"nan": float("nan")})


def test_format_utc_always_prints_microseconds_and_z() -> None:
    assert format_utc(datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)) == "2026-01-02T03:04:05.000000Z"
    assert format_utc(datetime(5, 1, 2, 3, 4, 5, 7, tzinfo=UTC)) == "0005-01-02T03:04:05.000007Z"
    zero = timezone(timedelta(0), "zero")
    assert format_utc(datetime(2026, 1, 2, tzinfo=zero)) == "2026-01-02T00:00:00.000000Z"


def test_build_export_rejects_bad_arguments() -> None:
    graph = _demo_graph()
    with pytest.raises(TypeError):
        build_export(
            object(),  # type: ignore[arg-type]
            ExportArtifact.EVIDENCE_MANIFEST,
            audience=AccessClass.PUBLIC,
            generator_version=TEST_VERSION,
        )
    with pytest.raises(ValueError):
        build_export(
            graph,
            "secret",  # type: ignore[arg-type]
            audience=AccessClass.PUBLIC,
            generator_version=TEST_VERSION,
        )
    with pytest.raises(ValueError):
        build_export(
            graph,
            ExportArtifact.EVIDENCE_MANIFEST,
            audience="secret",  # type: ignore[arg-type]
            generator_version=TEST_VERSION,
        )
    for version in ("", "  ", None):
        with pytest.raises(ValueError):
            build_export(
                graph,
                ExportArtifact.EVIDENCE_MANIFEST,
                audience=AccessClass.PUBLIC,
                generator_version=version,  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------- envelope


def test_envelope_names_schema_generator_project_and_policy() -> None:
    graph = _demo_graph()
    for artifact, document in _all(graph, AccessClass.INTERNAL).items():
        assert document["schema"] == f"urn:asca:schema:{artifact.value}:v1"
        assert document["schema_version"] == "1.0.0"
        assert document["generator"] == {"name": "asca", "version": TEST_VERSION}
        assert document["project"] == {
            "id": DEMO_PROJECT_ID,
            "title": graph.project.title,
            "is_synthetic": True,
            "revision": graph.revision,
        }
        assert document["audience"] == "internal"
        assert document["policy_note"] == POLICY_NOTE


def test_synthetic_notice_is_present_exactly_for_synthetic_projects() -> None:
    complete, _ = _complete_graph()
    for audience in AccessClass:
        for document in _all(_demo_graph(), audience).values():
            assert document["synthetic_notice"] == SYNTHETIC_NOTICE
        for document in _all(complete, audience).values():
            assert document["synthetic_notice"] is None


# ---------------------------------------------------------------------- access rules


def test_demo_public_export_withholds_the_internal_memo_records() -> None:
    expected = [
        {"kind": "claim", "id": _demo(IdKind.CLAIM, 2), "access_class": "internal"},
        {"kind": "decision", "id": _demo(IdKind.DECISION, 2), "access_class": "internal"},
        {"kind": "source", "id": _demo(IdKind.SOURCE, 2), "access_class": "internal"},
        {
            "kind": "source_version",
            "id": _demo(IdKind.SOURCE_VERSION, 2),
            "access_class": "internal",
        },
        {
            "kind": "source_version",
            "id": _demo(IdKind.SOURCE_VERSION, 3),
            "access_class": "internal",
        },
    ]
    documents = _all(_demo_graph(), AccessClass.PUBLIC)
    manifest = documents[ExportArtifact.EVIDENCE_MANIFEST]
    records = documents[ExportArtifact.DECISION_RECORDS]
    withheld = sorted(
        [*manifest["withheld"], *records["withheld"]], key=lambda item: (item["kind"], item["id"])
    )
    assert withheld == sorted(expected, key=lambda item: (item["kind"], item["id"]))
    assert documents[ExportArtifact.VALIDATION_REPORT]["withheld"] == []
    assert [item["id"] for item in manifest["sources"]] == [_demo(IdKind.SOURCE, 1)]
    assert [item["id"] for item in manifest["claims"]] == [_demo(IdKind.CLAIM, 1)]
    assert [item["id"] for item in records["decisions"]] == [_demo(IdKind.DECISION, 1)]
    raw = b"".join(canonical_json(document) for document in documents.values())
    assert b"Pedestal values drift" not in raw
    assert b"Illustrative pedestal handling" not in raw


def test_demo_internal_export_includes_the_internal_memo_records() -> None:
    documents = _all(_demo_graph(), AccessClass.INTERNAL)
    manifest = documents[ExportArtifact.EVIDENCE_MANIFEST]
    records = documents[ExportArtifact.DECISION_RECORDS]
    assert manifest["withheld"] == [] and records["withheld"] == []
    memo = next(item for item in manifest["sources"] if item["id"] == _demo(IdKind.SOURCE, 2))
    assert [item["id"] for item in memo["versions"]] == [
        _demo(IdKind.SOURCE_VERSION, 2),
        _demo(IdKind.SOURCE_VERSION, 3),
    ]
    assert memo["versions"][0]["currency"] == {"scientific": "current", "technical": "superseded"}
    assert memo["versions"][0]["superseded_by"][0]["version_id"] == _demo(IdKind.SOURCE_VERSION, 3)
    assert _demo(IdKind.CLAIM, 2) in {item["id"] for item in manifest["claims"]}
    pedestal = next(
        item for item in records["decisions"] if item["id"] == _demo(IdKind.DECISION, 2)
    )
    assert pedestal["status"] == "unsupported"
    assert pedestal["effective_access_class"] == "internal"
    assert pedestal["status_reasons"] == ["no_evidence_links"]


def test_mixed_and_versionless_sources_follow_the_least_restrictive_version() -> None:
    service = make_service()
    pid = service.create_project("Access fixture project", is_synthetic=False)
    mixed = service.register_source(
        pid,
        SourceDraft(
            "Fixture mixed source",
            PersistentIdentifier(PidScheme.URL, "https://example.org/asca-test/mixed"),
        ),
    )
    public_v = service.add_source_version(
        pid, mixed, VersionDraft("v1", SourceAuthority.WORKING_MATERIAL, AccessClass.PUBLIC)
    )
    restricted_v = service.add_source_version(
        pid,
        mixed,
        VersionDraft(
            "v2",
            SourceAuthority.WORKING_MATERIAL,
            AccessClass.RESTRICTED,
            access_conditions="Fixture restricted condition.",
        ),
    )
    bare = service.register_source(
        pid,
        SourceDraft(
            "Fixture source without versions",
            PersistentIdentifier(PidScheme.URL, "https://example.org/asca-test/bare"),
        ),
    )
    graph = service.load(pid)

    public = _export(graph, ExportArtifact.EVIDENCE_MANIFEST, AccessClass.PUBLIC)
    by_id = {item["id"]: item for item in public["sources"]}
    assert [item["id"] for item in by_id[mixed]["versions"]] == [public_v]
    assert by_id[bare]["versions"] == []
    assert public["withheld"] == [
        {"kind": "source_version", "id": restricted_v, "access_class": "restricted"}
    ]
    internal = _export(graph, ExportArtifact.EVIDENCE_MANIFEST, AccessClass.INTERNAL)
    assert internal["withheld"] == public["withheld"]
    full = _export(graph, ExportArtifact.EVIDENCE_MANIFEST, AccessClass.RESTRICTED)
    assert full["withheld"] == []
    by_id = {item["id"]: item for item in full["sources"]}
    assert [item["id"] for item in by_id[mixed]["versions"]] == [public_v, restricted_v]


def test_withheld_kinds_cover_exactly_the_access_controlled_records() -> None:
    assert [kind.value for kind in WithheldKind] == [
        "source",
        "source_version",
        "claim",
        "decision",
        "test_case",
    ]


# ---------------------------------------------------------------------- content


def test_complete_project_decision_records() -> None:
    graph, names = _complete_graph()
    records = _export(graph, ExportArtifact.DECISION_RECORDS, AccessClass.RESTRICTED)
    by_id = {item["id"]: item for item in records["decisions"]}
    assert [item["id"] for item in records["decisions"]] == [
        names.da,
        names.db,
        names.dc,
        names.dd,
        names.de,
        names.df,
    ]
    assert {key: by_id[key]["status"] for key in by_id} == {
        names.da: "approved",
        names.db: "approved",
        names.dc: "proposed",
        names.dd: "unsupported",
        names.de: "rejected",
        names.df: "unsupported",
    }
    da = by_id[names.da]
    assert [item["link_id"] for item in da["evidence"]] == [names.da_support, names.da_context]
    assert da["evidence"][0]["claim_state"] == "source_text_checked"
    assert da["evidence"][0]["authority"] == "published"
    assert [item["freshness"] for item in da["implemented_by"]] == ["current"]
    assert [item["test_case_id"] for item in da["verified_by"]] == [names.test_analytic]
    assert [(item["id"], item["is_current"]) for item in da["reviews"]] == [
        (names.approval_da, True)
    ]
    assert by_id[names.db]["reviews"][0]["conflict_resolution"] is not None
    assert by_id[names.db]["effective_access_class"] == "internal"
    assert by_id[names.de]["reviews"][0]["verdict"] == "rejected"
    assert by_id[names.dc]["superseded_by"] == names.df
    assert by_id[names.df]["supersedes"] == names.dc
    freshness = {
        item["symbol_id"]: item["freshness"]
        for decision in records["decisions"]
        for item in decision["implemented_by"]
    }
    assert freshness == {
        names.symbol_current: "current",
        names.symbol_stale: "stale",
        names.symbol_moved: "moved",
        names.symbol_orphaned: "orphaned",
    }


def test_a_stale_approval_is_exported_as_not_current() -> None:
    service = make_service()
    names = build_complete_real_project(service)
    service.mark_claim_unavailable(names.project, names.journal_claim, reason="Fixture outage.")
    graph = service.load(names.project)
    records = _export(graph, ExportArtifact.DECISION_RECORDS, AccessClass.RESTRICTED)
    by_id = {item["id"]: item for item in records["decisions"]}
    da = by_id[names.da]
    assert da["status"] == "unsupported"
    assert da["approval_stale"] is True
    assert [(item["id"], item["is_current"]) for item in da["reviews"]] == [
        (names.approval_da, False)
    ]
    for decision in records["decisions"]:
        current = [item["id"] for item in decision["reviews"] if item["is_current"]]
        assert len(current) <= 1
        if decision["approval_stale"]:
            assert current == []


def test_export_orderings_follow_time_not_id() -> None:
    """Claims by (recorded_at, id), runs by (finished_at, id), implementations by revision.

    The step clock gives every record its own instant, so time order differs from id
    order and an id-ordered export would fail these checks.
    """
    service = make_service()
    names = build_complete_real_project(service)
    graph = service.load(names.project)
    # Two short runs on revision 1 that finish before the fixture's runs.
    extra_runs = [
        service.record_validation_run(
            names.project,
            RunDraft(
                revision_id=names.revision1,
                environment=EnvironmentDraft("3.12.3", "CPython", "Linux-x86_64", ()),
                origin=RunOrigin.EXECUTED,
                started_at=DEMO_TIME + timedelta(minutes=minutes),
                finished_at=DEMO_TIME + timedelta(minutes=minutes + 1),
                results=(TestResult(names.test_unit, TestOutcome.PASSED, None, None),),
            ),
        )
        for minutes in (20, 10)
    ]
    rev2_symbol = next(
        item
        for item in names.revision2_symbols
        if graph.get(CodeSymbol, item).qualified_name == "estimate_amplitude"
    )
    later_link = service.link_implementation(names.project, names.df, rev2_symbol)
    graph = service.load(names.project)

    manifest = _export(graph, ExportArtifact.EVIDENCE_MANIFEST, AccessClass.RESTRICTED)
    claim_ids = [item["id"] for item in manifest["claims"]]
    by_time = [
        item.id for item in sorted(graph.claims, key=lambda item: (item.recorded_at, item.id))
    ]
    assert claim_ids == by_time
    assert claim_ids != sorted(claim_ids)

    report = _export(graph, ExportArtifact.VALIDATION_REPORT, AccessClass.RESTRICTED)
    run_ids = [item["id"] for item in report["runs"]]
    assert run_ids == [extra_runs[1], extra_runs[0], names.run1, names.run2]
    assert run_ids != sorted(run_ids)

    records = _export(graph, ExportArtifact.DECISION_RECORDS, AccessClass.RESTRICTED)
    df = next(item for item in records["decisions"] if item["id"] == names.df)
    assert [(item["link_id"], item["revision_sequence"]) for item in df["implemented_by"]] == [
        (later_link, 2)
    ]


def test_complete_project_validation_report() -> None:
    graph, names = _complete_graph()
    report = _export(graph, ExportArtifact.VALIDATION_REPORT, AccessClass.RESTRICTED)
    assert report["withheld"] == []
    assert [item["id"] for item in report["environments"]] == [names.environment]
    assert [item["name"] for item in report["environments"][0]["packages"]] == [
        "asca-fixture",
        "numpy",
    ]
    tests = {item["id"]: item for item in report["test_cases"]}
    assert [item["node_id"] for item in report["test_cases"]] == sorted(
        item["node_id"] for item in report["test_cases"]
    )
    assert tests[names.test_regression]["latest"] == {
        "run_id": names.run2,
        "outcome": "failed",
        "origin": "imported",
    }
    assert tests[names.test_unit]["latest"]["run_id"] == names.run1
    assert tests[names.test_unit]["verifies"] == {
        "decision_ids": [],
        "symbol_ids": [names.symbol_moved],
    }
    assert tests[names.test_regression]["verifies"]["decision_ids"] == [names.db]
    assert [item["id"] for item in report["runs"]] == [names.run1, names.run2]
    first, second = report["runs"]
    assert (first["revision_sequence"], first["vcs_ref"]) == (1, "fixture-rev-1")
    assert (second["revision_sequence"], second["vcs_ref"]) == (2, None)
    assert second["summary"] == {
        "passed": 1,
        "failed": 1,
        "error": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
    }
    assert report["summary"] == {
        "test_case_count": 3,
        "run_count": 2,
        "latest_outcomes": {
            "passed": 2,
            "failed": 1,
            "error": 0,
            "skipped": 0,
            "xfailed": 0,
            "xpassed": 0,
            "not_run": 0,
        },
    }


def test_demo_validation_report_has_an_unrun_test() -> None:
    report = _export(_demo_graph(), ExportArtifact.VALIDATION_REPORT, AccessClass.PUBLIC)
    assert report["runs"] == [] and report["environments"] == []
    assert [item["latest"] for item in report["test_cases"]] == [None]
    assert report["summary"]["latest_outcomes"]["not_run"] == 1


def test_complete_project_manifest_versions_and_claims() -> None:
    graph, names = _complete_graph()
    manifest = _export(graph, ExportArtifact.EVIDENCE_MANIFEST, AccessClass.PUBLIC)
    versions = {
        version["id"]: version for source in manifest["sources"] for version in source["versions"]
    }
    journal = versions[names.journal_version]
    assert journal["authority_letter"] == "A"
    assert journal["published_on"] == "2024-01-15"
    assert journal["currency"] == {"scientific": "current", "technical": "superseded"}
    assert journal["superseded_by"][0]["version_id"] is None
    assert versions[names.working_version]["content_sha256"] is None
    assert versions[names.working_version]["retrieved_at"] is None
    assert names.internal_version not in versions
    claims = {item["id"]: item for item in manifest["claims"]}
    assert claims[names.working_claim]["verification"] == {
        "state": "not_checked",
        "normalization_version": 1,
        "checks": [],
    }
    check = claims[names.journal_claim]["verification"]["checks"][0]
    assert (check["sequence"], check["outcome"], check["method"]) == (
        1,
        "source_text_checked",
        "normalized_substring",
    )
    assert claims[names.implementation_claim]["locator"] == [
        {"kind": "path", "value": "src/reco/estimators.py"},
        {"kind": "line_range", "value": "2-2"},
    ]
    assert names.internal_claim not in claims


# ---------------------------------------------------------------------- references


def _assert_references_resolve(graph: ProvenanceGraph, audience: AccessClass) -> None:
    documents = _all(graph, audience)
    manifest = documents[ExportArtifact.EVIDENCE_MANIFEST]
    records = documents[ExportArtifact.DECISION_RECORDS]
    report = documents[ExportArtifact.VALIDATION_REPORT]
    withheld = {item["id"] for document in documents.values() for item in document["withheld"]}
    claims = {item["id"] for item in manifest["claims"]}
    versions = {v["id"] for source in manifest["sources"] for v in source["versions"]}
    decisions = {item["id"] for item in records["decisions"]}
    tests = {item["id"] for item in report["test_cases"]}
    assert not withheld & (claims | versions | decisions)
    for decision in records["decisions"]:
        for item in decision["evidence"]:
            assert item["claim_id"] in claims
        for item in decision["verified_by"]:
            assert item["test_case_id"] in tests
        for key in ("supersedes", "superseded_by"):
            assert decision[key] is None or decision[key] in decisions | withheld
    for claim in manifest["claims"]:
        assert claim["source_version_id"] in versions
    for version_id in (
        notice["version_id"]
        for source in manifest["sources"]
        for version in source["versions"]
        for notice in version["superseded_by"]
    ):
        assert version_id is None or version_id in versions | withheld
    for test in report["test_cases"]:
        assert set(test["verifies"]["decision_ids"]) <= decisions | withheld
        assert test["latest"] is None or test["latest"]["run_id"] in {
            run["id"] for run in report["runs"]
        }
    for run in report["runs"]:
        assert run["environment_id"] in {item["id"] for item in report["environments"]}


@pytest.mark.parametrize("audience", list(AccessClass))
def test_every_referenced_id_resolves_or_is_withheld(audience: AccessClass) -> None:
    _assert_references_resolve(_demo_graph(), audience)
    graph, _ = _complete_graph()
    _assert_references_resolve(graph, audience)


def test_synthetic_runs_count_as_not_run_in_the_summary() -> None:
    service = make_service()
    pid = service.create_project("Synthetic run fixture", is_synthetic=True)
    test = service.register_test_case(
        pid, node_id="tests/test_demo.py::test_demo", kind=TestKind.UNIT, description="Demo."
    )
    revision = service.record_workspace_revision(
        pid, vcs_ref=None, symbols=(), symbols_indexed=False
    )
    moment = datetime(2026, 11, 12, tzinfo=UTC)
    service.record_validation_run(
        pid,
        RunDraft(
            revision_id=revision.revision_id,
            environment=EnvironmentDraft("3.12.0", "CPython", "linux", ()),
            origin=RunOrigin.SYNTHETIC,
            started_at=moment,
            finished_at=moment,
            results=(TestResult(test, TestOutcome.PASSED, None, None),),
        ),
    )
    report = _export(service.load(pid), ExportArtifact.VALIDATION_REPORT, AccessClass.PUBLIC)
    outcomes = report["summary"]["latest_outcomes"]
    assert outcomes["passed"] == 0
    assert outcomes["not_run"] == 1
    [case] = report["test_cases"]
    assert case["latest"]["origin"] == "synthetic"
