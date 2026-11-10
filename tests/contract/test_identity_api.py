"""Identity capability must never imply a working CERN login during Phase 1A.1."""

from fastapi.testclient import TestClient


def test_identity_status_is_explicitly_disabled(client: TestClient) -> None:
    response = client.get("/api/v1/identity/status")
    assert response.status_code == 200
    assert response.json() == {
        "provider": "cern",
        "status": "not_configured",
        "authentication_enabled": False,
        "protocol": "oidc_authorization_code_pkce",
        "note": "OIDC contracts only; login, callbacks and token exchange are disabled.",
    }
    assert response.headers["Cache-Control"] == "no-store"


def test_cern_sso_capability_remains_unimplemented(client: TestClient) -> None:
    items = client.get("/api/v1/system/capabilities").json()["items"]
    assert next(item for item in items if item["id"] == "cern_sso")["status"] == "not_implemented"


def test_no_login_callback_or_token_exchange_routes(client: TestClient) -> None:
    for route in (
        "/api/v1/identity/login",
        "/api/v1/identity/callback",
        "/api/v1/identity/token",
    ):
        assert client.get(route).status_code == 404
        assert client.post(route).status_code == 404


def test_openapi_exposes_only_read_only_identity_status(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    assert set(spec["paths"]["/api/v1/identity/status"]) == {"get"}
