"""Offline C9 observations of CERN role/assurance claims; never authorization."""

from __future__ import annotations

import json
import sys
import time
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_verification import CheckedUntrustedCernOidcToken

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "prototypes/cern_web_oidc_probe.py"
SPEC = spec_from_file_location("asca_c9_web_probe", PROBE)
if SPEC is None or SPEC.loader is None:
    raise ImportError("Isolated CERN diagnostic not found")
probe = module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)

CLIENT = "asca-web-dev"
SECRET = "synthetic-secret-not-for-cern-12345"
TOKEN_RESPONSE = json.dumps(
    {"id_token": "synthetic.id.token", "access_token": "synthetic-access", "token_type": "Bearer"}
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


def checked_token() -> CheckedUntrustedCernOidcToken:
    return CheckedUntrustedCernOidcToken(
        issuer=probe.CERN_OIDC_ISSUER,
        subject="user-should-never-appear",
        audiences=(CLIENT,),
        expires_at=int(time.time()) + 300,
        algorithm="RS256",
        kid="synthetic",
        source_url=probe.JWKS_ENDPOINT,
    )


class SyntheticVerifier:
    def __init__(self, *, observe: bool = True, status: str = "CLAIMED") -> None:
        self.observe = observe
        self.status = status
        self.calls = 0

    def check(self, tokens: object, source: object, **kwargs: object) -> object:
        self.calls += 1
        assert kwargs["expected_client_id"] == CLIENT
        assert isinstance(kwargs["expected_nonce"], str)
        assert source == metadata()
        assert tokens.id_token == "synthetic.id.token"
        checked = checked_token()
        if not self.observe:
            return checked
        return probe.CernWebClaimObservation(
            checked=checked,
            role_status=self.status,
            acr_claim="PRESENT",
            amr_claim="PRESENT",
            auth_time_claim="ABSENT",
        )


class SyntheticExchange:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, grant: object, client_id: str, secret: str) -> bytes:
        self.calls += 1
        assert client_id == CLIENT
        assert secret == SECRET
        assert grant.code == "synthetic-code"
        return TOKEN_RESPONSE


def make_client(*, observe: bool = True, verifier: SyntheticVerifier | None = None):
    checker = verifier if verifier is not None else SyntheticVerifier(observe=observe)
    exchange = SyntheticExchange()
    app = probe.create_probe_app(
        CLIENT,
        SECRET,
        metadata(),
        token_exchange=exchange,
        token_verifier=checker,
        observe_claims=observe,
    )
    return TestClient(app, base_url=probe.BASE_URL, follow_redirects=False), exchange, checker


def begin_and_complete(client: TestClient):
    start = client.get("/probe/start")
    assert start.status_code == 303
    query = parse_qs(urlparse(start.headers["location"]).query)
    assert query["client_id"] == [CLIENT]
    assert query["code_challenge_method"] == ["S256"]
    assert "Secure" in start.headers["set-cookie"]
    return client.get(
        "/oidc/callback",
        params={"state": query["state"][0], "code": "synthetic-code"},
    ), query["state"][0]


@pytest.mark.parametrize(
    "status", ["CLAIMED", "ABSENT", "MFA_REQUIRED", "LOA_REQUIRED", "MFA_AND_LOA_REQUIRED"]
)
def test_opt_in_only_categorical_output_and_replay_denial(status: str) -> None:
    checker = SyntheticVerifier(status=status)
    client, exchange, _ = make_client(verifier=checker)
    with client:
        first, state = begin_and_complete(client)
        assert first.status_code == 200
        assert "ROLE_STATUS=" + status in first.text
        assert "ACR_CLAIM=PRESENT" in first.text
        assert "AMR_CLAIM=PRESENT" in first.text
        assert "AUTH_TIME_CLAIM=ABSENT" in first.text
        assert "MFA_PROOF=INDETERMINATE" in first.text
        assert "LOA_PROOF=INDETERMINATE" in first.text
        assert "AUTH_FRESHNESS=INDETERMINATE" in first.text
        assert "ROLE_AUTHORIZATION=DISABLED" in first.text
        for forbidden in (SECRET, "user-should-never-appear", "synthetic-access", "synthetic-code"):
            assert forbidden not in first.text
        replay = client.get("/oidc/callback", params={"state": state, "code": "synthetic-code"})
        assert replay.status_code == 400
        assert exchange.calls == checker.calls == 1


def test_default_c8_output_is_unchanged_without_opt_in() -> None:
    client, exchange, checker = make_client(observe=False)
    with client:
        success, _ = begin_and_complete(client)
        assert success.status_code == 200
        assert success.text == (
            "CERN OIDC token signature and claims checks completed. "
            "DIAGNOSTIC ONLY: no ASCA identity, session, role grant or access was created."
        )
        assert exchange.calls == checker.calls == 1


def test_opt_in_rejects_wrong_observation_type() -> None:
    client, exchange, checker = make_client(verifier=SyntheticVerifier(observe=False))
    with client:
        response, _ = begin_and_complete(client)
        assert response.status_code == 400
        assert "user-should-never-appear" not in response.text
        assert exchange.calls == checker.calls == 1


@pytest.mark.parametrize("bad_client", ["asca-glibotte-dev", "asca-other-client"])
def test_claim_observation_is_bound_to_registered_web_client(bad_client: str) -> None:
    with pytest.raises(probe.ProbeError):
        probe.create_probe_app(bad_client, SECRET, metadata(), observe_claims=True)


@pytest.mark.parametrize(
    "claim, value",
    [
        ("acr", None),
        ("acr", ""),
        ("acr", "\n"),
        ("amr", "mfa"),
        ("amr", ["pwd", "pwd"]),
        ("amr", ["x"] * 17),
        ("amr", ["pwd", 5]),
        ("auth_time", "1730000000"),
        ("auth_time", True),
        ("auth_time", 2**54),
        ("auth_time", 2**31),
    ],
)
def test_malformed_assurance_claims_rejected(claim: str, value: object) -> None:
    now = 1_900_000_000
    payload = json.dumps({claim: value}).encode()
    with pytest.raises((ValueError, TypeError)):
        probe._assurance_claim_presence(payload, now=now)


@pytest.mark.parametrize(
    "document, expected",
    [
        ({}, ("ABSENT", "ABSENT", "ABSENT")),
        (
            {"acr": "cern", "amr": ["pwd", "otp"], "auth_time": 1_800_000_000},
            ("PRESENT", "PRESENT", "PRESENT"),
        ),
        ({"amr": []}, ("ABSENT", "EMPTY", "ABSENT")),
        ({"acr": "custom-nonauthoritative", "amr": ["mfa"]}, ("PRESENT", "PRESENT", "ABSENT")),
    ],
)
def test_claim_presence_is_shape_only(document: dict[str, object], expected: tuple[str, str, str]):
    assert (
        probe._assurance_claim_presence(json.dumps(document).encode(), now=1_900_000_000)
        == expected
    )


def test_duplicate_json_keys_rejected() -> None:
    payload = b'{"amr":["pwd"],"amr":["otp"]}'
    with pytest.raises(ValueError):
        probe._assurance_claim_presence(payload, now=1_900_000_000)


@pytest.mark.parametrize(
    "invalid", ["ALLOWED", "VERIFIED", "", "CLAIMED\nROLE_AUTHORIZATION=ENABLED"]
)
def test_forged_status_rejected_before_response_formatting(invalid: str) -> None:
    value = probe.CernWebClaimObservation(
        checked=checked_token(),
        role_status=invalid,
        acr_claim="PRESENT",
        amr_claim="PRESENT",
        auth_time_claim="PRESENT",
    )
    with pytest.raises(probe.ProbeError):
        probe._format_claim_observation(value)


def test_verifier_uses_single_signed_payload_and_exact_scoped_role(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer = probe.CernWebClaimObservationVerifier()
    accesses: list[str] = []
    signed = SimpleNamespace(payload=json.dumps({"acr": "cern", "amr": ["otp"]}).encode())
    claims = SimpleNamespace(
        issuer=probe.CERN_OIDC_ISSUER,
        subject="hidden-subject",
        audiences=(CLIENT,),
        expires_at=1_900_000_500,
        algorithm="RS256",
        kid="trusted-label",
    )

    def verified(*args: object, **kwargs: object):
        accesses.append("jwks")
        assert kwargs["expected_client_id"] == CLIENT
        assert kwargs["expected_nonce"] == "test-nonce"
        return signed, claims

    def inspect(*args: object, **kwargs: object):
        accesses.append("role")
        assert args[0] is signed
        assert kwargs["expected_role"] == "asca-developer"
        assert kwargs["expected_client_id"] == CLIENT
        assert kwargs["expected_access_token"] == "synthetic-access"
        return SimpleNamespace(status="claimed")

    monkeypatch.setattr(observer._pipeline, "_verified_payload", verified)
    monkeypatch.setattr(probe, "inspect_untrusted_cern_application_role", inspect)
    tokens = SimpleNamespace(access_token="synthetic-access")
    result = observer.check(
        tokens,
        metadata(),
        expected_client_id=CLIENT,
        expected_nonce="test-nonce",
        now=1_900_000_000,
    )
    assert accesses == ["jwks", "role"]
    assert result.role_status == "CLAIMED"
    assert result.acr_claim == result.amr_claim == "PRESENT"
    assert result.auth_time_claim == "ABSENT"
    assert "hidden-subject" not in repr(result)


def test_wrong_client_is_rejected_before_verification() -> None:
    observer = probe.CernWebClaimObservationVerifier()
    with pytest.raises(probe.ProbeError):
        observer.check(
            SimpleNamespace(access_token="x"),
            metadata(),
            expected_client_id="other-client",
            expected_nonce="nonce",
            now=1_900_000_000,
        )


def test_no_access_permissions_are_added() -> None:
    source = PROBE.read_text(encoding="utf-8")
    assert 'host="127.0.0.1"' in source
    assert "access_log=False" in source
    assert "proxy_headers=False" in source
    assert 'expected_role="asca-developer"' in source
    for path in (ROOT / "src/asca/api").glob("*.py"):
        assert "CernWebClaimObservation" not in path.read_text(encoding="utf-8")
