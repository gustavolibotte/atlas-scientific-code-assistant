"""Contract regression: production API still has no OIDC login/callback endpoints."""

from fastapi.testclient import TestClient

from asca.api.main import create_app


def test_oidc_callback_transport_is_not_mounted_in_production_app() -> None:
    with TestClient(create_app()) as client:
        for path in (
            "/api/v1/identity/login",
            "/api/v1/identity/callback",
            "/api/v1/identity/token",
        ):
            assert client.get(path).status_code == 404
            assert client.post(path).status_code == 404
        status = client.get("/api/v1/identity/status")
        assert status.status_code == 200
        assert status.json()["authentication_enabled"] is False
        capabilities = client.get("/api/v1/system/capabilities").json()["items"]
        assert (
            next(item for item in capabilities if item["id"] == "cern_sso")["status"]
            == "not_implemented"
        )
        spec = client.get("/openapi.json").json()
        assert all("/identity/callback" not in key for key in spec["paths"])


def test_only_read_only_identity_status_is_present() -> None:
    with TestClient(create_app()) as client:
        result = client.get("/openapi.json")
        assert set(result.json()["paths"]["/api/v1/identity/status"]) == {"get"}
