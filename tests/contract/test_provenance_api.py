"""HTTP contract of the read-only provenance inspection routes."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator
from provenance_builders import (
    CompleteProject,
    CountingIdFactory,
    StepClock,
    build_complete_real_project,
    fingerprint,
)

from asca.api.main import create_app
from asca.application.demo import DEMO_DECISION_ID, DEMO_PROJECT_ID
from asca.application.inspection import InspectionWarning
from asca.application.provenance import ProvenanceService, SymbolDraft
from asca.domain.provenance import (
    POLICY_NOTE,
    REVIEW_NOTE,
    SYNTHETIC_NOTICE,
    ApprovalVerdict,
    DecisionStatus,
    FileIssue,
    FileIssueKind,
    FingerprintAlgorithm,
    Language,
    LinkFreshness,
    SourceAuthority,
    SourceSpan,
    Stance,
    StatusReason,
    SymbolKind,
)

pytestmark = pytest.mark.contract

NEW_PATHS = (
    "/api/v1/projects",
    "/api/v1/projects/{project_id}/symbols",
    "/api/v1/projects/{project_id}/symbols/{symbol_id}/inspection",
    "/api/v1/projects/{project_id}/exports/{artifact}",
)

PROJECT_KEYS = {"id", "title", "is_synthetic", "revision", "created_at"}
REVISION_KEYS = {
    "id",
    "sequence",
    "vcs_ref",
    "symbols_indexed",
    "source_digest",
    "file_issue_count",
}
SYMBOL_KEYS = {
    "id",
    "qualified_name",
    "file_path",
    "kind",
    "language",
    "span",
    "fingerprint",
    "fingerprint_algorithm",
    "revision",
}
SUMMARY_KEYS = {
    "id",
    "qualified_name",
    "file_path",
    "kind",
    "language",
    "decision_count",
    "worst_freshness",
}
INSPECTION_KEYS = {
    "project",
    "disclaimer",
    "policy_note",
    "review_note",
    "symbol",
    "decisions",
    "direct_tests",
    "warnings",
    "file_issue",
}
LISTING_KEYS = {"project", "revision", "items", "file_issues", "links"}
LOCATION_KEYS = {"symbol_id", "qualified_name", "file_path", "kind", "span", "revision_sequence"}
IMPLEMENTATION_KEYS = {
    "link_id",
    "freshness",
    "created_at",
    "freshness_reason",
    "linked_symbol",
    "current_symbol",
    "last_seen_symbol",
    "lost_in_revision_sequence",
    "candidates",
    "file_issue",
}
LINK_HEALTH_KEYS = {
    "link_id",
    "decision_id",
    "decision_title",
    "freshness",
    "freshness_reason",
    "linked_symbol",
    "current_symbol",
    "created_at",
}
DECISION_KEYS = {
    "id",
    "title",
    "statement",
    "rationale",
    "alternatives",
    "assumptions",
    "access_floor",
    "effective_access_class",
    "status",
    "evidential_status",
    "status_reasons",
    "approval_stale",
    "supersedes",
    "superseded_by",
    "implementation",
    "evidence",
    "tests",
    "reviews",
    "warnings",
}
EVIDENCE_KEYS = {
    "link_id",
    "stance",
    "asserted_by",
    "note",
    "counts_as_support",
    "claim",
    "source",
    "version",
}
CLAIM_KEYS = {"id", "quote", "locator", "statement", "extracted_by", "state", "last_check"}
CHECK_KEYS = {"sequence", "outcome", "method", "checked_at", "detail"}
SOURCE_KEYS = {"id", "title", "persistent_id", "is_synthetic"}
VERSION_KEYS = {
    "id",
    "version_label",
    "authority",
    "authority_letter",
    "access_class",
    "access_conditions",
    "authority_basis",
    "content_sha256",
    "retrieved_at",
    "published_on",
    "scientific_currency",
    "technical_currency",
    "superseded_by",
}
SUPERSESSION_KEYS = {"dimension", "superseding_version_id", "reason", "recorded_at"}
TEST_KEYS = {"id", "node_id", "kind", "description", "latest"}
RUN_KEYS = {
    "run_id",
    "origin",
    "outcome",
    "finished_at",
    "revision_sequence",
    "environment_id",
    "is_latest_revision",
}
REVIEW_KEYS = {
    "id",
    "sequence",
    "verdict",
    "reviewer",
    "rationale",
    "conflict_resolution",
    "reviewed_at",
    "is_current",
}


def _symbols(client: TestClient, project_id: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/projects/{project_id}/symbols")
    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    return body


def _inspection(client: TestClient, project_id: str, symbol_id: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/projects/{project_id}/symbols/{symbol_id}/inspection")
    assert response.status_code == 200
    body: dict[str, Any] = response.json()
    return body


@pytest.fixture(scope="module")
def complete_client() -> tuple[TestClient, CompleteProject]:
    app = create_app(clock=StepClock(), ids=CountingIdFactory())
    service: ProvenanceService = app.state.provenance_service
    names = build_complete_real_project(service)
    with TestClient(app) as client:
        yield client, names


# ---------------------------------------------------------------------- demo


def test_projects_list_the_demo_as_synthetic(client: TestClient) -> None:
    response = client.get("/api/v1/projects")
    assert response.status_code == 200
    items = response.json()["items"]
    assert [item["id"] for item in items] == [DEMO_PROJECT_ID]
    (demo,) = items
    assert set(demo) == PROJECT_KEYS
    assert demo["is_synthetic"] is True
    assert demo["revision"] >= 1


def test_demo_symbols_to_inspection_round_trip(client: TestClient) -> None:
    listing = _symbols(client, DEMO_PROJECT_ID)
    assert set(listing) == LISTING_KEYS
    assert listing["file_issues"] == []
    assert [item["freshness"] for item in listing["links"]] == ["unknown", "unknown"]
    assert {item["freshness_reason"] for item in listing["links"]} == {"not_fingerprinted"}
    assert listing["project"]["id"] == DEMO_PROJECT_ID
    assert set(listing["revision"]) == REVISION_KEYS
    assert [item["qualified_name"] for item in listing["items"]] == [
        "estimate_amplitude",
        "subtract_pedestal",
    ]
    symbol = listing["items"][0]
    assert set(symbol) == SUMMARY_KEYS
    assert symbol["decision_count"] == 1
    assert symbol["worst_freshness"] == LinkFreshness.UNKNOWN.value

    body = _inspection(client, DEMO_PROJECT_ID, symbol["id"])
    assert set(body) == INSPECTION_KEYS
    assert body["disclaimer"] == SYNTHETIC_NOTICE
    assert body["policy_note"] == POLICY_NOTE
    assert body["review_note"] == REVIEW_NOTE
    assert body["warnings"] == [InspectionWarning.SYNTHETIC_PROJECT.value]
    assert body["symbol"]["id"] == symbol["id"]
    assert body["direct_tests"] == []
    (decision,) = body["decisions"]
    assert decision["id"] == DEMO_DECISION_ID
    assert decision["status"] == DecisionStatus.SUPPORTED.value
    assert decision["implementation"]["freshness"] == LinkFreshness.UNKNOWN.value
    assert decision["implementation"]["freshness_reason"] == "not_fingerprinted"
    assert body["file_issue"] is None
    assert decision["warnings"] == [
        "decision_not_reviewed",
        "link_unknown_freshness",
        "test_not_run",
    ]
    (evidence,) = decision["evidence"]
    assert evidence["claim"]["state"] == "source_text_checked"
    assert evidence["counts_as_support"] is True
    assert evidence["source"]["is_synthetic"] is True
    (test,) = decision["tests"]
    assert test["latest"] is None
    assert decision["reviews"] == []


def test_demo_unsupported_decision_is_returned_in_local_mode(client: TestClient) -> None:
    listing = _symbols(client, DEMO_PROJECT_ID)
    pedestal = next(
        item for item in listing["items"] if item["qualified_name"] == "subtract_pedestal"
    )
    (decision,) = _inspection(client, DEMO_PROJECT_ID, pedestal["id"])["decisions"]
    assert decision["status"] == DecisionStatus.UNSUPPORTED.value
    assert decision["status_reasons"] == [StatusReason.NO_EVIDENCE_LINKS.value]
    # Local single-user mode returns every access class.
    assert decision["effective_access_class"] == "internal"
    assert decision["evidence"][0]["version"]["access_class"] == "internal"


# ---------------------------------------------------------------------- complete project


def test_complete_project_symbols_listing(
    complete_client: tuple[TestClient, CompleteProject],
) -> None:
    client, names = complete_client
    listing = _symbols(client, names.project)
    assert listing["project"]["is_synthetic"] is False
    assert listing["revision"]["id"] == names.revision2
    assert listing["revision"]["sequence"] == 2
    assert listing["revision"]["vcs_ref"] is None
    table = {
        (item["file_path"], item["qualified_name"]): (
            item["decision_count"],
            item["worst_freshness"],
        )
        for item in listing["items"]
    }
    assert table == {
        ("src/reco/calibration.py", "calibrate"): (1, "moved"),
        ("src/reco/estimators.py", "estimate_amplitude"): (1, "current"),
        ("src/reco/estimators.py", "subtract_pedestal"): (1, "stale"),
    }
    assert set(listing) == LISTING_KEYS
    assert set(listing["revision"]) == REVISION_KEYS
    assert listing["revision"]["source_digest"] is None
    assert listing["revision"]["file_issue_count"] == 0
    assert listing["file_issues"] == []
    links = listing["links"]
    for item in links:
        assert set(item) == LINK_HEALTH_KEYS
        assert set(item["linked_symbol"]) == LOCATION_KEYS
    assert [
        (item["link_id"], item["decision_id"], item["freshness"], item["freshness_reason"])
        for item in links
    ] == [
        (names.link_orphaned, names.de, "orphaned", "removed"),
        (names.link_stale, names.db, "stale", "content_changed"),
        (names.link_moved, names.dd, "moved", "relocated"),
        (names.link_current, names.da, "current", "unchanged"),
    ]
    assert [item["decision_title"] for item in links] == [
        "De rejected shortcut",
        "Db pedestal handling",
        "Dd automated optimality",
        "Da weighted estimator",
    ]
    orphaned, _, moved, current = links
    assert orphaned["current_symbol"] is None
    assert orphaned["linked_symbol"] == {
        "symbol_id": names.symbol_orphaned,
        "qualified_name": "LegacyFit.fit",
        "file_path": "src/reco/estimators.py",
        "kind": "method",
        "span": None,
        "revision_sequence": 1,
    }
    assert moved["linked_symbol"]["file_path"] == "src/reco/estimators.py"
    assert moved["current_symbol"]["file_path"] == "src/reco/calibration.py"
    assert moved["current_symbol"]["revision_sequence"] == 2
    assert current["current_symbol"]["span"] == {"start_line": 1, "end_line": 3}


def test_complete_project_inspection_key_sets_and_enum_values(
    complete_client: tuple[TestClient, CompleteProject],
) -> None:
    client, names = complete_client
    body = _inspection(client, names.project, names.symbol_current)
    assert set(body) == INSPECTION_KEYS
    assert body["disclaimer"] is None
    assert body["warnings"] == []
    assert set(body["project"]) == PROJECT_KEYS
    assert set(body["symbol"]) == SYMBOL_KEYS
    assert set(body["symbol"]["revision"]) == REVISION_KEYS
    assert body["symbol"]["fingerprint_algorithm"] is None
    assert body["file_issue"] is None
    assert body["symbol"]["span"] == {"start_line": 1, "end_line": 3}
    assert body["symbol"]["kind"] == "function"
    assert body["symbol"]["language"] == "python"
    assert body["symbol"]["revision"]["id"] == names.revision1

    (decision,) = body["decisions"]
    assert set(decision) == DECISION_KEYS
    assert decision["id"] == names.da
    assert decision["status"] == DecisionStatus.APPROVED.value
    assert decision["evidential_status"] == DecisionStatus.SUPPORTED.value
    assert decision["approval_stale"] is False
    assert StatusReason.APPROVAL_CURRENT.value in decision["status_reasons"]
    assert decision["warnings"] == ["source_technically_superseded"]
    implementation = decision["implementation"]
    assert set(implementation) == IMPLEMENTATION_KEYS
    assert implementation["link_id"] == names.link_current
    assert implementation["freshness"] == "current"
    assert implementation["freshness_reason"] == "unchanged"
    assert set(implementation["linked_symbol"]) == LOCATION_KEYS
    assert implementation["linked_symbol"]["symbol_id"] == names.symbol_current
    assert implementation["linked_symbol"]["revision_sequence"] == 1
    assert implementation["current_symbol"]["revision_sequence"] == 2
    assert implementation["current_symbol"]["qualified_name"] == "estimate_amplitude"
    assert implementation["last_seen_symbol"] == implementation["current_symbol"]
    assert implementation["lost_in_revision_sequence"] is None
    assert implementation["candidates"] == []
    assert implementation["file_issue"] is None

    support, context = decision["evidence"]
    for item in (support, context):
        assert set(item) == EVIDENCE_KEYS
        assert set(item["claim"]) == CLAIM_KEYS
        assert set(item["source"]) == SOURCE_KEYS
        assert set(item["version"]) == VERSION_KEYS
    assert [support["stance"], context["stance"]] == [Stance.SUPPORTS, Stance.CONTEXT]
    assert [support["counts_as_support"], context["counts_as_support"]] == [True, False]
    assert set(support["claim"]["last_check"]) == CHECK_KEYS
    assert support["claim"]["locator"] == [
        {"kind": "page", "value": "3"},
        {"kind": "section", "value": "3"},
    ]
    assert support["source"]["persistent_id"] == {"scheme": "doi", "value": "10.5555/asca-test.1"}
    version = support["version"]
    assert version["authority"] == SourceAuthority.PUBLISHED.value
    assert version["authority_letter"] == "A"
    assert version["published_on"] == "2024-01-15"
    assert version["scientific_currency"] == "current"
    assert version["technical_currency"] == "superseded"
    (notice,) = version["superseded_by"]
    assert set(notice) == SUPERSESSION_KEYS
    assert notice["dimension"] == "technical"
    assert notice["superseding_version_id"] is None
    assert context["claim"]["state"] == "not_checked"
    assert context["claim"]["last_check"] is None

    (test,) = decision["tests"]
    assert set(test) == TEST_KEYS
    assert test["id"] == names.test_analytic
    assert test["kind"] == "analytic"
    assert set(test["latest"]) == RUN_KEYS
    assert test["latest"]["run_id"] == names.run2
    assert test["latest"]["origin"] == "imported"
    assert test["latest"]["outcome"] == "passed"
    assert test["latest"]["revision_sequence"] == 2
    assert test["latest"]["environment_id"] == names.environment
    assert test["latest"]["is_latest_revision"] is True

    (review,) = decision["reviews"]
    assert set(review) == REVIEW_KEYS
    assert review["id"] == names.approval_da
    assert review["verdict"] == ApprovalVerdict.APPROVED.value
    assert review["is_current"] is True
    assert review["conflict_resolution"] is None


def test_complete_project_test_and_review_details(
    complete_client: tuple[TestClient, CompleteProject],
) -> None:
    client, names = complete_client
    moved = _inspection(client, names.project, names.symbol_moved)
    assert moved["warnings"] == ["test_result_outdated"]
    (direct,) = moved["direct_tests"]
    assert direct["id"] == names.test_unit
    assert direct["latest"]["run_id"] == names.run1
    assert direct["latest"]["origin"] == "executed"
    assert direct["latest"]["revision_sequence"] == 1
    assert direct["latest"]["is_latest_revision"] is False
    (dd,) = moved["decisions"]
    assert dd["implementation"]["freshness"] == "moved"
    assert dd["implementation"]["freshness_reason"] == "relocated"
    assert dd["implementation"]["current_symbol"]["file_path"] == "src/reco/calibration.py"
    assert dd["evidence"][0]["version"]["authority_letter"] == "E"
    assert dd["evidence"][0]["asserted_by"] == "automated"
    assert dd["evidence"][0]["claim"]["extracted_by"] == "automated"

    stale = _inspection(client, names.project, names.symbol_stale)
    (db,) = stale["decisions"]
    assert db["status"] == "approved"
    assert db["evidential_status"] == "conflicting"
    assert db["reviews"][0]["conflict_resolution"] is not None
    assert db["tests"][0]["latest"]["outcome"] == "failed"
    assert db["warnings"] == ["link_stale", "test_failing"]

    orphaned = _inspection(client, names.project, names.symbol_orphaned)
    (de,) = orphaned["decisions"]
    assert de["status"] == "rejected"
    assert de["implementation"]["freshness"] == "orphaned"
    assert de["implementation"]["freshness_reason"] == "removed"
    assert de["implementation"]["lost_in_revision_sequence"] == 2
    assert de["implementation"]["current_symbol"] is None
    assert de["implementation"]["last_seen_symbol"]["symbol_id"] == names.symbol_orphaned
    (rejection,) = de["reviews"]
    assert rejection["verdict"] == "rejected"
    assert rejection["is_current"] is True


def test_a_stale_approval_is_shown_as_not_current() -> None:
    app = create_app(clock=StepClock(), ids=CountingIdFactory())
    service: ProvenanceService = app.state.provenance_service
    names = build_complete_real_project(service)
    service.mark_claim_unavailable(names.project, names.journal_claim, reason="Fixture outage.")
    with TestClient(app) as client:
        body = _inspection(client, names.project, names.symbol_current)
    (decision,) = body["decisions"]
    assert decision["id"] == names.da
    assert decision["status"] == DecisionStatus.UNSUPPORTED.value
    assert decision["approval_stale"] is True
    assert "approval_stale" in decision["warnings"]
    assert [(item["id"], item["is_current"]) for item in decision["reviews"]] == [
        (names.approval_da, False)
    ]


def test_lineage_fields_for_algorithm_change_and_ambiguous_relocation() -> None:
    app = create_app(clock=StepClock(), ids=CountingIdFactory())
    service: ProvenanceService = app.state.provenance_service
    names = build_complete_real_project(service)
    estimators = "src/reco/estimators.py"
    digest = "d" * 64
    calibrate = SymbolDraft(
        Language.PYTHON,
        SymbolKind.FUNCTION,
        "calibrate",
        "src/reco/calibration.py",
        SourceSpan(1, 4),
        fingerprint(3),
        FingerprintAlgorithm.PYTHON_AST_1,
    )
    rev3 = service.record_workspace_revision(
        names.project,
        vcs_ref="fixture-rev-3",
        symbols=[calibrate],
        symbols_indexed=True,
        file_issues=[FileIssue(estimators, FileIssueKind.SYNTAX_ERROR)],
        source_digest=digest,
    )
    rev4 = service.record_workspace_revision(
        names.project,
        vcs_ref="fixture-rev-4",
        symbols=[
            calibrate,
            *(
                SymbolDraft(
                    Language.PYTHON,
                    SymbolKind.FUNCTION,
                    name,
                    estimators,
                    SourceSpan(1, 3),
                    fingerprint(1),
                )
                for name in ("estimate_amplitude_b", "estimate_amplitude_a")
            ),
        ],
        symbols_indexed=True,
    )
    with TestClient(app) as client:
        listing = _symbols(client, names.project)
        body = _inspection(client, names.project, names.symbol_current)
        calibrated = _inspection(client, names.project, rev3.symbol_ids[0])

    # The rev3 symbol carries the algorithm id; its revision carries the digest and issue.
    assert calibrated["symbol"]["fingerprint_algorithm"] == FingerprintAlgorithm.PYTHON_AST_1.value
    assert calibrated["symbol"]["revision"]["source_digest"] == digest
    assert calibrated["symbol"]["revision"]["file_issue_count"] == 1
    assert calibrated["file_issue"] is None
    (dd,) = calibrated["decisions"]
    # rev2 had no algorithm; rev4 has python-ast/1, so the fingerprints do not compare.
    assert dd["implementation"]["freshness"] == "unknown"
    assert dd["implementation"]["freshness_reason"] == "algorithm_changed"

    # rev4 parses estimators.py again: two plausible equal-fingerprint candidates appear.
    assert listing["revision"]["id"] == rev4.revision_id
    assert listing["revision"]["file_issue_count"] == 0
    assert listing["file_issues"] == []
    assert body["file_issue"] is None
    (da,) = body["decisions"]
    implementation = da["implementation"]
    assert implementation["freshness"] == "orphaned"
    assert implementation["freshness_reason"] == "ambiguous_relocation"
    assert implementation["current_symbol"] is None
    assert implementation["lost_in_revision_sequence"] == 4
    assert [item["qualified_name"] for item in implementation["candidates"]] == [
        "estimate_amplitude_a",
        "estimate_amplitude_b",
    ]
    for item in implementation["candidates"]:
        assert set(item) == LOCATION_KEYS
        assert item["revision_sequence"] == 4
    assert implementation["file_issue"] is None
    health = {item["link_id"]: item for item in listing["links"]}
    assert health[names.link_current]["freshness_reason"] == "ambiguous_relocation"
    assert health[names.link_current]["current_symbol"] is None


def test_file_not_parsed_reports_the_file_issue() -> None:
    app = create_app(clock=StepClock(), ids=CountingIdFactory())
    service: ProvenanceService = app.state.provenance_service
    names = build_complete_real_project(service)
    estimators = "src/reco/estimators.py"
    service.record_workspace_revision(
        names.project,
        vcs_ref="fixture-rev-3",
        symbols=[
            SymbolDraft(
                Language.PYTHON,
                SymbolKind.FUNCTION,
                "calibrate",
                "src/reco/calibration.py",
                None,
                fingerprint(3),
            ),
        ],
        symbols_indexed=True,
        file_issues=[FileIssue(estimators, FileIssueKind.TOO_LARGE)],
    )
    with TestClient(app) as client:
        listing = _symbols(client, names.project)
        body = _inspection(client, names.project, names.symbol_stale)
    assert listing["file_issues"] == [{"file_path": estimators, "kind": "too_large"}]
    assert listing["revision"]["file_issue_count"] == 1
    assert body["file_issue"] == FileIssueKind.TOO_LARGE.value
    (db,) = body["decisions"]
    implementation = db["implementation"]
    assert implementation["freshness"] == "unknown"
    assert implementation["freshness_reason"] == "file_not_parsed"
    assert implementation["file_issue"] == "too_large"
    assert implementation["current_symbol"] is None
    assert implementation["last_seen_symbol"]["revision_sequence"] == 2
    assert implementation["lost_in_revision_sequence"] is None
    reasons = {item["link_id"]: item["freshness_reason"] for item in listing["links"]}
    assert reasons == {
        names.link_current: "file_not_parsed",
        names.link_stale: "file_not_parsed",
        names.link_moved: "relocated",
        names.link_orphaned: "removed",
    }


def test_unknown_symbol_in_known_project_is_not_found(client: TestClient) -> None:
    response = client.get(f"/api/v1/projects/{DEMO_PROJECT_ID}/symbols/sym_{'0' * 32}/inspection")
    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}


def test_unknown_project_is_not_found(client: TestClient) -> None:
    for path in (
        f"/api/v1/projects/prj_{'0' * 32}/symbols",
        f"/api/v1/projects/prj_{'0' * 32}/symbols/sym_{'0' * 32}/inspection",
    ):
        response = client.get(path)
        assert response.status_code == 404
        assert response.json() == {"detail": "Not found"}


def test_project_without_revisions_lists_no_symbols() -> None:
    app = create_app(seed_demo=False)
    service: ProvenanceService = app.state.provenance_service
    project = service.create_project("Empty fixture project", is_synthetic=False)
    with TestClient(app) as client:
        listing = _symbols(client, project)
        assert listing["revision"] is None
        assert listing["items"] == []
        projects = client.get("/api/v1/projects").json()["items"]
        assert [item["id"] for item in projects] == [project]
        assert projects[0]["revision"] == 0


# ---------------------------------------------------------------------- app surface


def test_capabilities_add_provenance_store_and_keep_provenance_demo_only(
    client: TestClient,
) -> None:
    items = client.get("/api/v1/system/capabilities").json()["items"]
    ids = [item["id"] for item in items]
    assert ids.index("provenance_store") == ids.index("provenance") + 1
    statuses = {item["id"]: item["status"] for item in items}
    assert statuses["provenance_store"] == "available"
    assert statuses["provenance"] == "demo_only"


def test_openapi_contains_the_new_paths_as_get_only(client: TestClient) -> None:
    paths = client.get("/openapi.json").json()["paths"]
    for path in NEW_PATHS:
        assert path in paths
        assert set(paths[path]) == {"get"}
        assert paths[path]["get"]["tags"] == ["provenance"]


def test_new_operations_are_listed_as_get_only_api_routes() -> None:
    """Route-allowlist checks enumerate ``app.routes``; included routers must stay visible."""
    operations = {
        (route.path, method)
        for route in create_app().routes
        if isinstance(route, APIRoute)
        for method in route.methods or set()
    }
    assert {(path, "GET") for path in NEW_PATHS} <= operations
    assert not {(path, method) for path, method in operations if path in NEW_PATHS} - {
        (path, "GET") for path in NEW_PATHS
    }


def test_symbol_index_adds_no_route_and_no_write_method() -> None:
    """M2 indexing has no HTTP trigger: the project route set stays exactly GET-only."""
    operations = {
        (route.path, method)
        for route in create_app().routes
        if isinstance(route, APIRoute) and route.path.startswith("/api/v1/projects")
        for method in route.methods or set()
    }
    assert operations == {(path, "GET") for path in NEW_PATHS}
    assert not any("index" in path for path, _ in operations)


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/projects/prj_x/symbols",
        f"/api/v1/projects/{DEMO_PROJECT_ID}/symbols/sym_x/inspection",
        f"/api/v1/projects/{DEMO_PROJECT_ID}/exports/unknown",
        f"/api/v1/projects/{DEMO_PROJECT_ID}/exports/evidence_manifest?audience=everyone",
    ],
)
def test_validation_errors_match_the_published_openapi_schema(
    client: TestClient, path: str
) -> None:
    spec = client.get("/openapi.json").json()
    response = client.get(path)
    assert response.status_code == 422
    validator = Draft202012Validator(
        {"$ref": "#/components/schemas/HTTPValidationError", "components": spec["components"]}
    )
    errors = list(validator.iter_errors(response.json()))
    assert errors == []
    for name in NEW_PATHS[1:]:
        documented = spec["paths"][name]["get"]["responses"]["422"]
        assert documented["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/HTTPValidationError"
        }
