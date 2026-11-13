"""Negative tests for the read-only provenance routes."""

from __future__ import annotations

from collections.abc import Mapping

import pytest
from fastapi.testclient import TestClient

from asca.api.main import create_app
from asca.application.demo import DEMO_PROJECT_ID
from asca.application.errors import StoredGraphIntegrityError
from asca.application.ports import ProjectSummary
from asca.application.provenance import ProvenanceService
from asca.domain.provenance import ProjectId, ProvenanceGraph, ProvenanceRecord
from asca.infrastructure.system import SystemClock, Uuid4IdFactory

pytestmark = pytest.mark.security

VALID_PROJECT = DEMO_PROJECT_ID
VALID_SYMBOL = f"sym_{'a' * 32}"
UNTRUSTED_ORIGIN = "https://untrusted.example.invalid"


def _routes(project_id: str = VALID_PROJECT, symbol_id: str = VALID_SYMBOL) -> list[str]:
    return [
        "/api/v1/projects",
        f"/api/v1/projects/{project_id}/symbols",
        f"/api/v1/projects/{project_id}/symbols/{symbol_id}/inspection",
        f"/api/v1/projects/{project_id}/exports/evidence_manifest",
    ]


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("path", _routes())
def test_write_methods_are_not_allowed(client: TestClient, method: str, path: str) -> None:
    assert client.request(method, path).status_code == 405


BAD_PROJECT_IDS = [
    VALID_PROJECT.upper(),
    f"prj_{'a' * 30}..",
    f"prj_{'a' * 31}",
    f"prj_{'a' * 33}",
    f"sym_{'a' * 32}",
    f"PRJ_{'a' * 32}",
    f"prj_{'g' * 32}",
]
BAD_SYMBOL_IDS = [
    VALID_SYMBOL.upper(),
    f"sym_{'a' * 30}..",
    f"sym_{'a' * 31}",
    f"sym_{'a' * 33}",
    f"prj_{'a' * 32}",
    f"dec_{'a' * 32}",
]


@pytest.mark.parametrize("project_id", BAD_PROJECT_IDS)
def test_malformed_project_ids_are_rejected(client: TestClient, project_id: str) -> None:
    for path in _routes(project_id=project_id)[1:]:
        assert client.get(path).status_code == 422


@pytest.mark.parametrize("symbol_id", BAD_SYMBOL_IDS)
def test_malformed_symbol_ids_are_rejected(client: TestClient, symbol_id: str) -> None:
    path = f"/api/v1/projects/{VALID_PROJECT}/symbols/{symbol_id}/inspection"
    assert client.get(path).status_code == 422


@pytest.mark.parametrize(
    "path",
    [
        f"/api/v1/projects/prj_{'a' * 14}%2F{'a' * 15}/symbols",
        f"/api/v1/projects/{VALID_PROJECT}/symbols/sym_{'a' * 14}%2F{'a' * 15}/inspection",
        f"/api/v1/projects/prj_{'a' * 12}%2F..%2F{'a' * 12}/symbols",
    ],
)
def test_encoded_slashes_never_reach_a_handler(client: TestClient, path: str) -> None:
    # Starlette decodes %2F before routing, so no provenance route matches.
    response = client.get(path)
    assert response.status_code in (404, 422)
    assert "aaaaaaaaaaaa" not in response.text


def _assert_generic(body: str, *secrets: str) -> None:
    for secret in secrets:
        assert secret not in body
    assert "sqlite" not in body.lower()
    assert "traceback" not in body.lower()


def test_not_found_bodies_do_not_echo_ids(client: TestClient) -> None:
    unknown_project = f"prj_{'b' * 32}"
    unknown_symbol = f"sym_{'c' * 32}"
    for path in _routes(project_id=unknown_project, symbol_id=unknown_symbol)[1:]:
        response = client.get(path)
        assert response.status_code == 404
        assert response.json() == {"detail": "Not found"}
        _assert_generic(response.text, unknown_project, unknown_symbol)
    response = client.get(f"/api/v1/projects/{VALID_PROJECT}/symbols/{unknown_symbol}/inspection")
    assert response.status_code == 404
    _assert_generic(response.text, unknown_symbol, VALID_PROJECT)


class _CorruptRepository:
    """A repository whose stored graph fails integrity validation."""

    def create_project(self, project: object) -> None:
        raise NotImplementedError

    def list_projects(self) -> list[ProjectSummary]:
        return []

    def load(self, project_id: ProjectId) -> ProvenanceGraph:
        cause = ValueError(f"sqlite3 row for {project_id} at /tmp/asca.db\nTraceback (fake)")
        raise StoredGraphIntegrityError() from cause

    def append(
        self, project_id: ProjectId, expected_revision: int, records: list[ProvenanceRecord]
    ) -> int:
        raise NotImplementedError


def test_integrity_errors_are_generic_500s() -> None:
    app = create_app(seed_demo=False)
    app.state.provenance_service = ProvenanceService(
        _CorruptRepository(), SystemClock(), Uuid4IdFactory()
    )
    with TestClient(app) as client:
        for path in _routes()[1:]:
            response = client.get(path)
            assert response.status_code == 500
            assert response.json() == {"detail": "Provenance store integrity error"}
            _assert_generic(response.text, VALID_PROJECT, VALID_SYMBOL, "/tmp")
            assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize("path", _routes())
def test_untrusted_cors_origin_is_not_allowed(client: TestClient, path: str) -> None:
    response = client.get(path, headers={"Origin": UNTRUSTED_ORIGIN})
    assert "access-control-allow-origin" not in response.headers
    preflight = client.options(
        path,
        headers={"Origin": UNTRUSTED_ORIGIN, "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in preflight.headers


def _assert_security_headers(headers: Mapping[str, str]) -> None:
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"


def test_security_headers_on_inspection_and_export_responses(client: TestClient) -> None:
    listing = client.get(f"/api/v1/projects/{VALID_PROJECT}/symbols").json()
    symbol_id = listing["items"][0]["id"]
    inspection = client.get(f"/api/v1/projects/{VALID_PROJECT}/symbols/{symbol_id}/inspection")
    assert inspection.status_code == 200
    _assert_security_headers(inspection.headers)
    # The export body belongs to the export workstream; only headers are asserted here.
    export = client.get(f"/api/v1/projects/{VALID_PROJECT}/exports/evidence_manifest")
    _assert_security_headers(export.headers)
    for path in _routes()[:2]:
        _assert_security_headers(client.get(path).headers)
