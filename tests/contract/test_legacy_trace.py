"""The frozen legacy demo trace contract, now served from stored provenance."""

import json
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from provenance_builders import (
    ENVIRONMENT,
    CompleteProject,
    build_complete_real_project,
    make_service,
)

from asca.api.legacy import legacy_trace_from_graph
from asca.api.main import create_app
from asca.application.demo import DEMO_TIME, DeterministicIdFactory, FixedClock
from asca.application.errors import StoredGraphIntegrityError
from asca.application.provenance import ProvenanceService, RunDraft
from asca.domain.provenance import RunOrigin, TestOutcome, TestResult

pytestmark = pytest.mark.contract

GOLDEN = Path(__file__).parent / "golden" / "demo_trace_legacy.json"


def test_legacy_trace_matches_the_golden_file(client: TestClient) -> None:
    response = client.get("/api/v1/demo/trace")
    assert response.status_code == 200
    assert response.json() == json.loads(GOLDEN.read_text(encoding="utf-8"))


def test_legacy_trace_does_not_depend_on_the_injected_clock_or_ids() -> None:
    app = create_app(clock=FixedClock(DEMO_TIME), ids=DeterministicIdFactory("other"))
    with TestClient(app) as client:
        body = client.get("/api/v1/demo/trace").json()
    assert body == json.loads(GOLDEN.read_text(encoding="utf-8"))


def test_openapi_keeps_the_legacy_enums(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    schemas = spec["components"]["schemas"]
    assert schemas["EvidenceAuthority"]["enum"] == [
        "published",
        "documented",
        "implementation",
        "unverified",
    ]
    assert schemas["VerificationState"]["enum"] == [
        "not_run",
        "passed",
        "failed",
        "human_review_required",
    ]
    assert spec["paths"]["/api/v1/demo/trace"]["get"]["deprecated"] is True


def test_legacy_route_is_deprecated_and_read_only() -> None:
    routes = [
        route
        for route in create_app().routes
        if isinstance(route, APIRoute) and route.path == "/api/v1/demo/trace"
    ]
    assert len(routes) == 1
    assert routes[0].deprecated is True
    assert routes[0].methods == {"GET"}


def test_unseeded_app_has_no_in_code_fixture() -> None:
    with TestClient(create_app(seed_demo=False)) as client:
        response = client.get("/api/v1/demo/trace")
    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}


def _complete() -> tuple[ProvenanceService, CompleteProject]:
    service = make_service()
    return service, build_complete_real_project(service)


def test_legacy_mapping_of_real_authorities_and_results() -> None:
    service, names = _complete()
    graph = service.load(names.project)
    trace = legacy_trace_from_graph(graph, names.db)
    assert trace.is_synthetic is False
    assert {item.authority for item in trace.evidence} == {"documented", "implementation"}
    assert all(item.is_real_source for item in trace.evidence)
    assert [item.revision for item in trace.symbols] == ["fixture-rev-1"]
    assert [item.state for item in trace.verifications] == ["failed"]
    published = legacy_trace_from_graph(graph, names.da)
    assert [item.authority for item in published.evidence] == ["published"]
    assert published.evidence[0].locator == "10.5555/asca-test.1 journal · page=3; section=3"
    assert [item.state for item in published.verifications] == ["passed"]
    assert published.decision.evidence_ids == (names.journal_claim,)
    moved = legacy_trace_from_graph(graph, names.dd)
    assert [item.authority for item in moved.evidence] == ["unverified"]
    assert [item.id for item in moved.verifications] == [names.test_unit]
    assert [item.state for item in moved.verifications] == ["passed"]


def test_legacy_mapping_of_review_outcomes_and_unnamed_revisions() -> None:
    service, names = _complete()
    service.record_validation_run(
        names.project,
        RunDraft(
            revision_id=names.revision2,
            environment=ENVIRONMENT,
            origin=RunOrigin.EXECUTED,
            started_at=DEMO_TIME.replace(year=2027),
            finished_at=DEMO_TIME.replace(year=2027),
            results=(TestResult(names.test_unit, TestOutcome.XFAILED, None, None),),
        ),
    )
    graph = service.load(names.project)
    trace = legacy_trace_from_graph(graph, names.dd)
    assert [item.state for item in trace.verifications] == ["human_review_required"]
    rev2_symbol = names.revision2_symbols[0]
    service.link_implementation(names.project, names.df, rev2_symbol)
    trace = legacy_trace_from_graph(service.load(names.project), names.df)
    assert [item.revision for item in trace.symbols] == ["rev-2"]
    assert trace.evidence == []


def test_store_integrity_errors_map_to_a_generic_500() -> None:
    app = create_app()

    class _CorruptService:
        def load(self, project_id: str) -> object:
            raise StoredGraphIntegrityError() from ValueError(f"sqlite row for {project_id}")

    app.state.provenance_service = _CorruptService()
    with TestClient(app) as client:
        response = client.get("/api/v1/demo/trace")
    assert response.status_code == 500
    assert response.json() == {"detail": "Provenance store integrity error"}
    assert "prj_" not in response.text and "sqlite" not in response.text
