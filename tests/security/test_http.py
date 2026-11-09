"""Negative tests and baseline HTTP security controls."""

from fastapi.testclient import TestClient


def test_security_headers(client: TestClient) -> None:
    response = client.get("/api/v1/health/live")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"


def test_untrusted_cors_origin_is_not_allowed(client: TestClient) -> None:
    response = client.get(
        "/api/v1/health/live", headers={"Origin": "https://untrusted.example.invalid"}
    )
    assert "access-control-allow-origin" not in response.headers


def test_only_explicit_local_cors_origins(client: TestClient) -> None:
    response = client.get("/api/v1/health/live", headers={"Origin": "http://localhost:5173"})
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_read_only_endpoints_reject_writes(client: TestClient) -> None:
    assert client.post("/api/v1/demo/trace", json={}).status_code == 405
    assert client.delete("/api/v1/system/capabilities").status_code == 405
