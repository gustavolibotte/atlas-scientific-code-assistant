"""Offline adversarial checks of the unmounted CERN web diagnostic probe (C8)."""

from __future__ import annotations

import json
import re
import stat
import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "prototypes/cern_web_oidc_probe.py"
SPEC = spec_from_file_location("asca_c8_web_probe", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise ImportError("Isolated C8 probe not available")
probe = module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)

CLIENT_ID = "asca-web-dev"
SECRET = "offline-test-secret-1234567890"
TOKEN_BYTES = json.dumps(
    {"id_token": "aaa.bbb.ccc", "access_token": "synthetic-access-token", "token_type": "Bearer"}
).encode("utf-8")


def metadata() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=probe.CERN_OIDC_ISSUER,
        authorization_endpoint=probe.AUTH_ENDPOINT,
        token_endpoint=probe.TOKEN_ENDPOINT,
        jwks_uri=probe.JWKS_ENDPOINT,
        approved_id_token_algorithms=("RS256",),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


class FakeVerifier:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.nonces: list[str] = []

    def check(
        self,
        tokens: object,
        meta: OidcProviderMetadata,
        *,
        expected_client_id: str,
        expected_nonce: str,
        now: int,
    ) -> CheckedUntrustedCernOidcToken:
        self.nonces.append(expected_nonce)
        if self.fail:
            raise ValueError("synthetic-secret-should-not-leak")
        assert meta.issuer == probe.CERN_OIDC_ISSUER
        assert expected_client_id == CLIENT_ID
        assert now > 0
        return CheckedUntrustedCernOidcToken(
            issuer=probe.CERN_OIDC_ISSUER,
            subject="synthetic-subject",
            audiences=(expected_client_id,),
            expires_at=now + 300,
            algorithm="RS256",
            kid="synthetic",
            source_url=probe.JWKS_ENDPOINT,
        )


class FakeExchange:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[str, str]] = []

    def __call__(self, grant: object, client_id: str, secret: str) -> bytes:
        assert client_id == CLIENT_ID
        assert secret == SECRET
        self.calls.append((grant.code, grant.nonce))
        if self.fail:
            raise ValueError("synthetic-token-secret-should-not-leak")
        return TOKEN_BYTES


def make_client(
    *, bad_verify: bool = False, bad_exchange: bool = False
) -> tuple[TestClient, FakeVerifier, FakeExchange]:
    verifier = FakeVerifier(fail=bad_verify)
    exchange = FakeExchange(fail=bad_exchange)
    app = probe.create_probe_app(
        CLIENT_ID,
        SECRET,
        metadata(),
        token_exchange=exchange,
        token_verifier=verifier,
    )
    return (
        TestClient(app, base_url=probe.BASE_URL, follow_redirects=False),
        verifier,
        exchange,
    )


def begin(client: TestClient) -> tuple[str, str]:
    started = client.get("/probe/start")
    assert started.status_code == 303
    location = started.headers["location"]
    parsed = urlparse(location)
    assert parsed.scheme == "https"
    assert parsed.netloc == "auth.cern.ch"
    assert parsed.path == "/auth/realms/cern/protocol/openid-connect/auth"
    query = parse_qs(parsed.query)
    assert query["client_id"] == [CLIENT_ID]
    assert query["redirect_uri"] == [probe.CALLBACK_URI]
    assert query["scope"] == ["openid"]
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", query["code_challenge"][0])
    assert "code_verifier" not in query
    assert "secret" not in location
    cookie = started.headers["set-cookie"]
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert "Domain=" not in cookie
    return query["state"][0], query["nonce"][0]


def test_complete_browser_bound_flow_is_non_authoritative_and_replay_safe() -> None:
    client, verifier, exchange = make_client()
    with client:
        status = client.get("/probe/status")
        assert status.status_code == 200
        assert status.json() == {
            "provider": "cern_pinned_issuer",
            "mode": "isolated_diagnostic_only",
            "client_type": "confidential",
            "asca_identity": "not_configured",
            "authorization": "disabled",
            "session": "disabled",
            "chatlas_access": "disabled",
        }
        state, nonce = begin(client)
        callback = "/oidc/callback"
        params = {"state": state, "code": "mock-only-code", "iss": probe.CERN_OIDC_ISSUER}
        first = client.get(callback, params=params)
        assert first.status_code == 200
        assert "no ASCA identity" in first.text
        assert "Max-Age=0" in first.headers["set-cookie"]
        assert SECRET not in first.text
        assert "synthetic-subject" not in first.text
        assert "synthetic-access-token" not in first.text
        assert verifier.nonces == [nonce]
        assert exchange.calls == [("mock-only-code", nonce)]
        assert client.get(callback, params=params).status_code == 400
        assert exchange.calls == [("mock-only-code", nonce)]


@pytest.mark.parametrize(
    "tampering", ["bad_state", "duplicate_state", "wrong_issuer", "missing_cookie"]
)
def test_bad_callbacks_never_exchange_a_code(tampering: str) -> None:
    client, _, exchange = make_client()
    with client:
        state, _ = begin(client)
        query = f"state={state}&code=mock-only-code"
        headers: dict[str, str] = {}
        if tampering == "bad_state":
            query = "state=" + "A" * 43 + "&code=mock-only-code"
        elif tampering == "duplicate_state":
            query += f"&state={state}"
        elif tampering == "wrong_issuer":
            query += "&iss=https%3A%2F%2Fevil.invalid"
        else:
            client.cookies.clear()
        result = client.get("/oidc/callback?" + query, headers=headers)
        assert result.status_code == 400
        assert not exchange.calls


@pytest.mark.parametrize("mode", ["verifier", "exchange"])
def test_untrusted_failures_are_sanitized_and_consume_once(mode: str) -> None:
    client, _, exchange = make_client(
        bad_verify=mode == "verifier", bad_exchange=mode == "exchange"
    )
    with client:
        state, _ = begin(client)
        params = {"state": state, "code": "mock-only-code"}
        first = client.get("/oidc/callback", params=params)
        assert first.status_code == 400
        assert "synthetic-token-secret" not in first.text
        assert "synthetic-secret" not in first.text
        assert SECRET not in first.text
        assert "Max-Age=0" in first.headers["set-cookie"]
        second = client.get("/oidc/callback", params=params)
        assert second.status_code == 400
        assert len(exchange.calls) == 1


def test_cern_authorization_denial_consumes_state() -> None:
    client, _, exchange = make_client()
    with client:
        state, _ = begin(client)
        denial = client.get("/oidc/callback", params={"state": state, "error": "access_denied"})
        assert denial.status_code == 400
        assert (
            client.get("/oidc/callback", params={"state": state, "code": "again"}).status_code
            == 400
        )
        assert exchange.calls == []


@pytest.mark.parametrize(
    "query",
    [
        "state=missing",
        "state=A%ZZ",
        "state=A%00",
        "state=x&code=c&extra=x",
        "",
        "state=x&code=x&error=x",
    ],
)
def test_malformed_callback_rejected(query: str) -> None:
    client, _, exchange = make_client()
    with client:
        response = client.get("/oidc/callback?" + query)
        assert response.status_code == 400
        assert exchange.calls == []


def test_localhost_https_only() -> None:
    app = probe.create_probe_app(
        CLIENT_ID, SECRET, metadata(), token_exchange=FakeExchange(), token_verifier=FakeVerifier()
    )
    with TestClient(app, base_url="http://localhost:8443") as c:
        assert c.get("/").status_code == 400
        assert c.get("/probe/start").status_code == 400
    with TestClient(app, base_url="https://example.org:8443") as c:
        assert c.get("/").status_code in (400, 403)


@pytest.mark.parametrize("client_id", ["asca-glibotte-dev", "", "client id with space"])
def test_native_or_invalid_client_ids_rejected(client_id: str) -> None:
    with pytest.raises(probe.ProbeError):
        probe.create_probe_app(client_id, SECRET, metadata())


@pytest.mark.parametrize("field", ["issuer", "token_endpoint", "jwks_uri", "supports_pkce_s256"])
def test_forged_provider_metadata_rejected(field: str) -> None:
    from dataclasses import replace

    original = metadata()
    value: object = False if field == "supports_pkce_s256" else "https://evil.invalid/endpoint"
    with pytest.raises(probe.ProbeError):
        probe.create_probe_app(CLIENT_ID, SECRET, replace(original, **{field: value}))


def test_secret_file_permissions_and_symlink_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "secret"
    target.write_text(SECRET, encoding="ascii")
    target.chmod(0o600)
    monkeypatch.setattr(probe, "SECRET_FILE", target)
    assert probe._safe_secret_file() == SECRET
    target.chmod(0o644)
    with pytest.raises(probe.ProbeError):
        probe._safe_secret_file()
    target.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(target)
    monkeypatch.setattr(probe, "SECRET_FILE", link)
    with pytest.raises(probe.ProbeError):
        probe._safe_secret_file()


def test_one_time_secret_provisioning_has_owner_only_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "secure" / "client_secret"
    monkeypatch.setattr(probe, "SECRET_FILE", target)
    monkeypatch.setattr(probe.getpass, "getpass", lambda _: SECRET)
    probe.provision_secret()
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_text(encoding="ascii") == SECRET
    assert SECRET not in capsys.readouterr().out
    with pytest.raises(probe.ProbeError):
        probe.provision_secret()


def test_no_credential_or_authorization_route_in_production() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert 'host="127.0.0.1"' in source
    assert "access_log=False" in source
    assert "proxy_headers=False" in source
    assert "--init-secret" in source
    assert "--preflight" in source
    assert "CERN_OIDC_ISSUER" in source
    assert "SESSION=DISABLED" in source or "ASCA_SESSION=DISABLED" in source
    for path in (ROOT / "src/asca/api").glob("*.py"):
        assert "cern_web_oidc_probe" not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("response_kind", ["ok", "redirect", "oversized", "wrong_content_type"])
def test_token_transport_is_pinned_bounded_and_never_sends_secret_in_body(
    response_kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import base64
    from types import SimpleNamespace
    from urllib.parse import parse_qs

    import httpx

    observations: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observations.append(str(request.url))
        assert request.method == "POST"
        assert str(request.url) == probe.TOKEN_ENDPOINT
        auth = request.headers["authorization"]
        assert auth.startswith("Basic ")
        credentials = base64.b64decode(auth[6:]).decode("utf-8")
        assert credentials == f"{CLIENT_ID}:{SECRET}"
        body = parse_qs(request.content.decode("ascii"))
        assert SECRET not in request.content.decode("ascii")
        assert body == {
            "grant_type": ["authorization_code"],
            "code": ["synthetic-code"],
            "code_verifier": ["V" * 48],
            "redirect_uri": [probe.CALLBACK_URI],
        }
        if response_kind == "redirect":
            return httpx.Response(302, headers={"Location": "https://evil.invalid/"})
        if response_kind == "oversized":
            return httpx.Response(
                200, headers={"Content-Type": "application/json"}, content=b"A" * 65_537
            )
        if response_kind == "wrong_content_type":
            return httpx.Response(200, headers={"Content-Type": "text/html"}, content=b"bad")
        return httpx.Response(
            200, headers={"Content-Type": "application/json"}, content=TOKEN_BYTES
        )

    original_client = httpx.Client
    monkeypatch.setattr(
        probe.httpx,
        "Client",
        lambda **kwargs: original_client(
            transport=httpx.MockTransport(handler),
            follow_redirects=kwargs["follow_redirects"],
            trust_env=kwargs["trust_env"],
            timeout=kwargs["timeout"],
        ),
    )
    fake_grant = SimpleNamespace(code="synthetic-code", code_verifier="V" * 48)
    if response_kind == "ok":
        assert probe.exchange_confidential_code(fake_grant, CLIENT_ID, SECRET) == TOKEN_BYTES
    else:
        with pytest.raises(probe.ProbeError):
            probe.exchange_confidential_code(fake_grant, CLIENT_ID, SECRET)
    assert observations == [probe.TOKEN_ENDPOINT]
