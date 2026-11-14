"""Offline negative contracts: CERN role diagnostics are not ASCA authorization."""

from __future__ import annotations

from dataclasses import fields

from fastapi.routing import APIRoute

from asca.api.main import create_app
from asca.api.schemas import CapabilityState, IdentityStatusResponse
from asca.domain.oidc_native_exchange import ExchangedUntrustedCernOidcToken
from asca.domain.oidc_role_claims import UntrustedCernRoleObservation
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken
from asca.infrastructure.oidc_native_exchange import CernOidcNativeCodeExchange
from asca.infrastructure.oidc_native_lifecycle import CernNativeCallbackLifecycle


def test_only_read_only_foundation_api_routes_are_exposed() -> None:
    """Do not accidentally mount a native diagnostic as an API login route."""
    app = create_app()
    operations = {
        (route.path, method)
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in route.methods or set()
    }
    assert operations == {
        ("/api/v1/health/live", "GET"),
        ("/api/v1/health/ready", "GET"),
        ("/api/v1/system/capabilities", "GET"),
        ("/api/v1/identity/status", "GET"),
        ("/api/v1/demo/trace", "GET"),
        ("/api/v1/projects", "GET"),
        ("/api/v1/projects/{project_id}/symbols", "GET"),
        ("/api/v1/projects/{project_id}/symbols/{symbol_id}/inspection", "GET"),
        ("/api/v1/projects/{project_id}/exports/{artifact}", "GET"),
    }


def test_identity_status_stays_explicitly_disabled() -> None:
    status = IdentityStatusResponse()
    assert status.provider == "cern"
    assert status.status == "not_configured"
    assert status.authentication_enabled is False
    assert CapabilityState.NOT_IMPLEMENTED.value == "not_implemented"


def test_role_observation_is_not_a_principal_or_authorization() -> None:
    observation = UntrustedCernRoleObservation(status="claimed")
    assert {item.name for item in fields(observation)} == {"status", "authorization", "login"}
    assert observation.authorization == "not_implemented"
    assert observation.login == "not_implemented"
    for name in (
        "subject",
        "principal",
        "session",
        "permission",
        "permissions",
        "access_token",
        "refresh_token",
        "authenticated",
        "authorized",
    ):
        assert not hasattr(observation, name)


def test_checked_and_exchanged_diagnostics_are_not_session_receipts() -> None:
    """Inspect type contracts only; no tokens or network operations required."""
    for type_ in (CheckedUntrustedCernOidcToken, ExchangedUntrustedCernOidcToken):
        names = {item.name for item in fields(type_)}
        assert "session" not in names
        assert "permissions" not in names
        assert "authenticated" not in names
        assert "authorization" not in names
        assert "access_token" not in names


def test_native_exchange_and_lifecycle_do_not_create_login_sessions() -> None:
    for type_ in (CernOidcNativeCodeExchange, CernNativeCallbackLifecycle):
        assert not hasattr(type_, "create_session")
        assert not hasattr(type_, "authorize")
        assert not hasattr(type_, "grant_permissions")
