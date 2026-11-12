"""Offline checks: C2 documentation cannot accidentally declare web login ready."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.routing import APIRoute

from asca.api.main import create_app
from asca.api.schemas import IdentityStatusResponse
from asca.domain.oidc_role_claims import UntrustedCernRoleObservation

ROOT = Path(__file__).resolve().parents[2]
SOURCE_KINDS = {"saved_public_document_snapshot", "published_example", "standard"}
REGISTER = ROOT / "docs/security/cern-web-oidc-evidence-register.json"
ADR = ROOT / "docs/adr/0032-cern-web-client-assurance-session-review.md"
REVIEW = ROOT / "docs/security/cern-web-oidc-review.md"


def test_all_ten_gates_remain_unattested_or_unimplemented() -> None:
    evidence = json.loads(REGISTER.read_text(encoding="utf-8"))
    assert evidence["phase"] == "1A.2.5C2"
    assert evidence["review_kind"] == "design_only"
    for field in (
        "web_client_registered",
        "positive_assurance_attested",
        "production_sessions_enabled",
        "asca_authorization_enabled",
        "chatlas_access_enabled",
    ):
        assert evidence[field] is False
    gates = evidence["gates"]
    assert len(gates) == 10
    assert {item["id"] for item in gates} == {f"G{i}" for i in range(1, 11)}
    assert {item["state"] for item in gates} <= {
        "not_attested",
        "not_implemented",
        "diagnostic_only",
        "partial_offline",
    }
    assert all(item["required_proof"] for item in gates)


def test_evidence_sources_have_provenance_and_restricted_claims() -> None:
    document = json.loads(REGISTER.read_text(encoding="utf-8"))
    sources = document["sources"]
    ids = {source["id"] for source in sources}
    assert len(ids) == len(sources)
    assert all(
        source["uri"].startswith("https://")
        and source["kind"] in SOURCE_KINDS
        and source["supports"]
        for source in sources
    )
    assert all(set(item["references"]) <= ids and item["references"] for item in document["gates"])
    assert all(
        source["snapshot_date"] is not None
        for source in sources
        if source["kind"] == "saved_public_document_snapshot"
    )
    content = REGISTER.read_text(encoding="utf-8")
    for forbidden in ('"client_secret"', '"access_token"', '"refresh_token"', '"id_token"'):
        assert forbidden not in content


def test_review_cannot_promote_diagnostics_to_authorization() -> None:
    adr = ADR.read_text(encoding="utf-8")
    review = REVIEW.read_text(encoding="utf-8")
    assert "not positive" in adr or "not positive" in review
    assert "`amr`/`acr`" in adr or "`amr`/`acr`" in review
    assert "`ROLE_STATUS=CLAIMED`" in review
    assert "client-credentials" in review.casefold()
    assert "## Decisions intentionally UNRESOLVED" in adr
    assert "G1" in adr and "G6" in adr and "G7" in adr


def test_api_has_no_web_login_and_role_observation_is_not_authority() -> None:
    routes = {
        (route.path, method)
        for route in create_app().routes
        if isinstance(route, APIRoute)
        for method in route.methods or set()
    }
    assert all(method == "GET" for _, method in routes)
    assert all("callback" not in path and "login" not in path for path, _ in routes)
    status = IdentityStatusResponse()
    assert status.authentication_enabled is False
    assert status.status == "not_configured"
    observation = UntrustedCernRoleObservation(status="claimed")
    assert observation.authorization == "not_implemented"
    assert observation.login == "not_implemented"
    assert not hasattr(observation, "session")
