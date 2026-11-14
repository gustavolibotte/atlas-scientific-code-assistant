"""HTTP contract of the export download route, on a minimal app with only that router."""

import json

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import asca
from asca.api.dependencies import register_provenance_error_handlers
from asca.api.export_routes import build_export_router
from asca.application.demo import (
    DEMO_PROJECT_ID,
    DEMO_TIME,
    DeterministicIdFactory,
    FixedClock,
    seed_synthetic_demo,
)
from asca.application.exports import ExportArtifact, build_export, canonical_json
from asca.application.provenance import ProvenanceService
from asca.domain.provenance import AccessClass
from asca.infrastructure.memory_provenance import InMemoryProvenanceRepository

pytestmark = pytest.mark.contract

ROUTE = "/api/v1/projects/{project_id}/exports/{artifact}"


def _app() -> FastAPI:
    repo = InMemoryProvenanceRepository()
    seed_synthetic_demo(repo)
    app = FastAPI()
    app.state.provenance_service = ProvenanceService(
        repo, FixedClock(DEMO_TIME), DeterministicIdFactory("export-api")
    )
    register_provenance_error_handlers(app)
    app.include_router(build_export_router())
    return app


@pytest.fixture
def export_client() -> TestClient:
    with TestClient(_app()) as value:
        yield value


def _url(artifact: str, project_id: str = DEMO_PROJECT_ID) -> str:
    return f"/api/v1/projects/{project_id}/exports/{artifact}"


@pytest.mark.parametrize("artifact", list(ExportArtifact))
@pytest.mark.parametrize("audience", list(AccessClass))
def test_response_bytes_are_the_canonical_export(
    export_client: TestClient, artifact: ExportArtifact, audience: AccessClass
) -> None:
    response = export_client.get(_url(artifact.value), params={"audience": audience.value})
    assert response.status_code == 200
    service: ProvenanceService = export_client.app.state.provenance_service  # type: ignore[attr-defined]
    expected = canonical_json(
        build_export(
            service.load(DEMO_PROJECT_ID),
            artifact,
            audience=audience,
            generator_version=asca.__version__,
        )
    )
    assert response.content == expected
    assert response.headers["content-type"] == "application/json"
    assert response.headers["x-asca-schema"] == f"urn:asca:schema:{artifact.value}:v1"
    assert (
        response.headers["content-disposition"] == f'attachment; filename="{artifact.value}.json"'
    )


def test_audience_defaults_to_public(export_client: TestClient) -> None:
    body = export_client.get(_url("decision_records")).json()
    assert body["audience"] == "public"
    assert [item["kind"] for item in body["withheld"]] == ["decision"]
    assert body["generator"] == {"name": "asca", "version": asca.__version__}


@pytest.mark.parametrize("audience", ["secret", "PUBLIC", "", "public "])
def test_invalid_audience_is_422(export_client: TestClient, audience: str) -> None:
    response = export_client.get(_url("evidence_manifest"), params={"audience": audience})
    assert response.status_code == 422


@pytest.mark.parametrize("artifact", ["secret", "evidence_manifest.json", "EVIDENCE_MANIFEST"])
def test_unknown_artifact_is_422(export_client: TestClient, artifact: str) -> None:
    assert export_client.get(_url(artifact)).status_code == 422


@pytest.mark.parametrize(
    "project_id",
    [
        "prj_" + "A" * 32,
        "prj_" + "0" * 31,
        "prj_" + "0" * 33,
        "src_" + "0" * 32,
        "prj_" + "0" * 30 + "..",
    ],
)
def test_malformed_project_id_is_422(export_client: TestClient, project_id: str) -> None:
    assert export_client.get(_url("evidence_manifest", project_id)).status_code == 422


def test_unknown_project_is_404_without_echo(export_client: TestClient) -> None:
    unknown = "prj_" + "0" * 32
    response = export_client.get(_url("evidence_manifest", unknown))
    assert response.status_code == 404
    assert response.json() == {"detail": "Not found"}
    assert unknown not in response.text


def test_route_is_get_only_and_documents_a_json_object(export_client: TestClient) -> None:
    routes = [
        route
        for route in build_export_router().routes
        if isinstance(route, APIRoute) and route.path == ROUTE
    ]
    assert len(routes) == 1 and routes[0].methods == {"GET"}
    spec = export_client.get("/openapi.json").json()
    operation = spec["paths"][ROUTE]
    assert set(operation) == {"get"}
    content = operation["get"]["responses"]["200"]["content"]
    assert content["application/json"]["schema"] == {"type": "object"}
    assert operation["get"]["tags"] == ["provenance"]
    response = export_client.post(_url("evidence_manifest"))
    assert response.status_code == 405


def test_export_body_is_parseable_json_with_a_trailing_newline(export_client: TestClient) -> None:
    response = export_client.get(_url("validation_report"))
    assert response.content.endswith(b"}\n")
    assert json.loads(response.content)["schema"] == "urn:asca:schema:validation_report:v1"
