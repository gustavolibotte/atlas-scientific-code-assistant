"""The composed application serves provenance from a persisted SQLite store (M1 exit)."""

from __future__ import annotations

import stat
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from provenance_builders import CountingIdFactory, StepClock, build_complete_real_project

from asca.api import main as api_main
from asca.api.main import (
    DATABASE_URL_ENV,
    DEFAULT_FILE_DATABASE_URL,
    create_app,
    create_app_from_environment,
)
from asca.application.demo import DEMO_PROJECT_ID
from asca.application.exports import ExportArtifact
from asca.application.provenance import ProvenanceService
from asca.infrastructure.persistence import SqliteProvenanceStore

pytestmark = pytest.mark.contract

TRACE = "/api/v1/demo/trace"
PROJECTS = "/api/v1/projects"


def _file_url(path: Path) -> str:
    return f"sqlite+pysqlite:///{path}"


def _json(client: TestClient, path: str) -> Any:
    response = client.get(path)
    assert response.status_code == 200, path
    return response.json()


def _revisions(client: TestClient) -> dict[str, int]:
    return {item["id"]: item["revision"] for item in _json(client, PROJECTS)["items"]}


def _symbol_id(client: TestClient, project_id: str, qualified_name: str) -> str:
    listing = _json(client, f"{PROJECTS}/{project_id}/symbols")
    return str(
        next(item["id"] for item in listing["items"] if item["qualified_name"] == qualified_name)
    )


def _snapshot(client: TestClient, project_id: str, symbol_id: str) -> dict[str, Any]:
    """Every read-only representation of the demo and of one stored project."""
    demo_symbol = _symbol_id(client, DEMO_PROJECT_ID, "estimate_amplitude")
    snapshot: dict[str, Any] = {
        "projects": _json(client, PROJECTS),
        "trace": _json(client, TRACE),
        "demo_symbols": _json(client, f"{PROJECTS}/{DEMO_PROJECT_ID}/symbols"),
        "demo_inspection": _json(
            client, f"{PROJECTS}/{DEMO_PROJECT_ID}/symbols/{demo_symbol}/inspection"
        ),
        "symbols": _json(client, f"{PROJECTS}/{project_id}/symbols"),
        "inspection": _json(client, f"{PROJECTS}/{project_id}/symbols/{symbol_id}/inspection"),
    }
    for artifact in ExportArtifact:
        for audience in ("public", "internal", "restricted"):
            response = client.get(
                f"{PROJECTS}/{project_id}/exports/{artifact.value}?audience={audience}"
            )
            assert response.status_code == 200
            snapshot[f"{artifact.value}:{audience}"] = response.content
    return snapshot


def test_stored_trace_survives_a_restart_on_the_same_file(tmp_path: Path) -> None:
    """Exit criterion: create, persist, reload and export a complete trace over HTTP."""
    url = _file_url(tmp_path / "asca.db")

    first = create_app(url, clock=StepClock(), ids=CountingIdFactory())
    service: ProvenanceService = first.state.provenance_service
    names = build_complete_real_project(service)
    with TestClient(first) as client:
        before = _snapshot(client, names.project, names.symbol_current)
        revisions_before = _revisions(client)

    assert set(revisions_before) == {DEMO_PROJECT_ID, names.project}
    assert before["trace"]["is_synthetic"] is True
    assert before["inspection"]["symbol"]["id"] == names.symbol_current
    assert before["inspection"]["disclaimer"] is None
    assert before["inspection"]["decisions"]

    # A second application on the same file re-seeds nothing and serves identical data.
    second = create_app(url)
    with TestClient(second) as client:
        after = _snapshot(client, names.project, names.symbol_current)
        assert _revisions(client) == revisions_before

    assert after == before


def test_the_legacy_trace_is_served_from_storage(tmp_path: Path) -> None:
    url = _file_url(tmp_path / "asca.db")
    with TestClient(create_app(url)) as client:
        seeded = _json(client, TRACE)
    with TestClient(create_app(url, seed_demo=False)) as client:
        assert _json(client, TRACE) == seeded
    with TestClient(create_app(seed_demo=False)) as client:
        assert client.get(TRACE).status_code == 404


def test_create_app_without_arguments_creates_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(DATABASE_URL_ENV, _file_url(tmp_path / "ignored.db"))
    with TestClient(create_app()) as client:
        assert _json(client, TRACE)["is_synthetic"] is True
        assert list(_revisions(client)) == [DEMO_PROJECT_ID]
    # create_app never reads the environment and the default database is in memory.
    assert list(tmp_path.iterdir()) == []


def test_create_app_from_environment_honours_the_database_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "configured" / "store.db"
    database.parent.mkdir()
    monkeypatch.setenv(DATABASE_URL_ENV, _file_url(database))
    with TestClient(create_app_from_environment()) as client:
        assert list(_revisions(client)) == [DEMO_PROJECT_ID]
    assert database.is_file()

    with TestClient(create_app(_file_url(database), seed_demo=False)) as client:
        assert list(_revisions(client)) == [DEMO_PROJECT_ID]


def test_create_app_from_environment_accepts_the_in_memory_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(DATABASE_URL_ENV, "sqlite+pysqlite:///:memory:")
    with TestClient(create_app_from_environment()) as client:
        assert list(_revisions(client)) == [DEMO_PROJECT_ID]
    assert list(tmp_path.iterdir()) == []


def test_default_environment_database_lives_in_a_private_local_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert DEFAULT_FILE_DATABASE_URL == "sqlite+pysqlite:///./.asca/asca.db"
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(DATABASE_URL_ENV, raising=False)
    with TestClient(create_app_from_environment()) as client:
        assert list(_revisions(client)) == [DEMO_PROJECT_ID]
    directory = tmp_path / ".asca"
    assert (directory / "asca.db").is_file()
    assert stat.S_IMODE(directory.stat().st_mode) & 0o077 == 0


def test_relative_database_url_creates_its_parent_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(DATABASE_URL_ENV, "sqlite+pysqlite:///data/local/asca.db")
    with TestClient(create_app_from_environment()) as client:
        assert list(_revisions(client)) == [DEMO_PROJECT_ID]
    assert (tmp_path / "data" / "local" / "asca.db").is_file()
    assert stat.S_IMODE((tmp_path / "data" / "local").stat().st_mode) & 0o077 == 0


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://user:secret@db.example.org/asca",
        "sqlite:///./.asca/asca.db",
        "sqlite+pysqlite:///./bad/secret.db?mode=ro",
        "",
    ],
)
def test_unsupported_environment_url_is_refused_without_side_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(DATABASE_URL_ENV, url)
    with pytest.raises(ValueError) as excinfo:
        create_app_from_environment()
    assert "secret" not in str(excinfo.value)
    if url:
        assert url not in str(excinfo.value)
    assert list(tmp_path.iterdir()) == []


def test_create_app_refuses_an_unsupported_url_without_echoing_it() -> None:
    url = "mysql://user:secret@db.example.org/asca"
    with pytest.raises(ValueError) as excinfo:
        create_app(url)
    assert "secret" not in str(excinfo.value)
    assert url not in str(excinfo.value)


def _count_disposals(monkeypatch: pytest.MonkeyPatch) -> list[SqliteProvenanceStore]:
    disposed: list[SqliteProvenanceStore] = []
    original = SqliteProvenanceStore.dispose

    def dispose(self: SqliteProvenanceStore) -> None:
        disposed.append(self)
        original(self)

    monkeypatch.setattr(SqliteProvenanceStore, "dispose", dispose)
    return disposed


def test_application_shutdown_disposes_the_store(monkeypatch: pytest.MonkeyPatch) -> None:
    disposed = _count_disposals(monkeypatch)
    app: FastAPI = create_app()
    with TestClient(app) as client:
        assert client.get(TRACE).status_code == 200
        assert disposed == []
    assert len(disposed) == 1


def test_failed_seeding_disposes_the_store(monkeypatch: pytest.MonkeyPatch) -> None:
    disposed = _count_disposals(monkeypatch)

    def fail(_repository: object) -> str:
        raise RuntimeError("seeding failed")

    monkeypatch.setattr(api_main, "seed_synthetic_demo", fail)
    with pytest.raises(RuntimeError, match="seeding failed"):
        create_app()
    assert len(disposed) == 1
