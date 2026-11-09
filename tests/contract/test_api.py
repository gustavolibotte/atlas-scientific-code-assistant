"""Stable API contract checks."""

from fastapi.testclient import TestClient


def test_liveness_and_readiness(client: TestClient) -> None:
    assert client.get("/api/v1/health/live").json() == {"status": "ok"}
    ready = client.get("/api/v1/health/ready")
    assert ready.status_code == 200
    assert ready.json()["version"] == "0.1.0"


def test_capabilities_disclose_implementation_state(client: TestClient) -> None:
    result = client.get("/api/v1/system/capabilities")
    assert result.status_code == 200
    items = {item["id"]: item["status"] for item in result.json()["items"]}
    assert items["foundation_api"] == "available"
    assert items["provenance"] == "demo_only"
    for key in ("cern_sso", "chatlas", "codegen", "execution"):
        assert items[key] == "not_implemented"


def test_trace_ids_resolve_and_are_explicitly_synthetic(client: TestClient) -> None:
    result = client.get("/api/v1/demo/trace")
    assert result.status_code == 200
    trace = result.json()
    assert trace["is_synthetic"] is True
    assert "no CERN source" in trace["disclaimer"]
    decision = trace["decision"]
    assert set(decision["evidence_ids"]) == {e["id"] for e in trace["evidence"]}
    assert set(decision["code_symbol_ids"]) == {s["id"] for s in trace["symbols"]}
    assert set(decision["verification_ids"]) == {v["id"] for v in trace["verifications"]}
    assert all(not e["is_real_source"] for e in trace["evidence"])


def test_openapi_documents_all_foundation_endpoints(client: TestClient) -> None:
    spec = client.get("/openapi.json").json()
    for route in (
        "/api/v1/health/live",
        "/api/v1/health/ready",
        "/api/v1/system/capabilities",
        "/api/v1/demo/trace",
    ):
        assert route in spec["paths"]
