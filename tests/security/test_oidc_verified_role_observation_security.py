"""Adversarial one-fetch role observation; all data and collaborators are synthetic."""

from __future__ import annotations

import base64
import hashlib
import json
import socket

import pytest

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_jwks import CERN_OIDC_JWKS_URI
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_jwks_http import FetchedUnverifiedOidcJwks
from asca.domain.oidc_jws import OidcJwsError, SignatureCheckedUntrustedOidcPayload
from asca.domain.oidc_token_response import ParsedUnverifiedOidcTokenResponse
from asca.domain.oidc_verification import OidcVerificationError
from asca.infrastructure import oidc_verification as verification_module
from asca.infrastructure.oidc_verification import CernOidcVerificationPipeline

CLIENT = "asca-glibotte-dev"
NONCE = "syntheticNonce_01234567890123456789012345"
ROLE = "asca-developer"
NOW = 1_800_000_000
TOKEN = "synthetic-access-token"


def metadata() -> OidcProviderMetadata:
    return OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_JWKS_URI,
        approved_id_token_algorithms=("RS256",),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )


def signed_claims(**changes: object) -> bytes:
    digest = hashlib.sha256(TOKEN.encode("ascii")).digest()
    at_hash = base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode("ascii")
    claims: dict[str, object] = {
        "iss": CERN_OIDC_ISSUER,
        "sub": "synthetic-subject",
        "aud": CLIENT,
        "nonce": NONCE,
        "iat": NOW - 30,
        "exp": NOW + 300,
        "at_hash": at_hash,
        "resource_access": {CLIENT: {"roles": [ROLE]}},
    }
    claims.update(changes)
    return json.dumps(claims).encode("utf-8")


def tokens(*, access_token: str = TOKEN) -> ParsedUnverifiedOidcTokenResponse:
    return ParsedUnverifiedOidcTokenResponse(
        access_token=access_token,
        id_token="a.b.c",
        token_type="Bearer",
        expires_in=300,
        refresh_token=None,
        scope=None,
    )


def prepared(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> tuple[CernOidcVerificationPipeline, dict[str, int]]:
    """Mock verifier functions only: wrappers cannot be used as CERN authority."""
    pipeline = CernOidcVerificationPipeline()
    steps = {"fetch": 0, "parse": 0, "signature": 0, "inspect": 0}

    def fetched(_metadata: object) -> FetchedUnverifiedOidcJwks:
        steps["fetch"] += 1
        return FetchedUnverifiedOidcJwks(b'{"keys":[]}', CERN_OIDC_JWKS_URI)

    def parsed(_raw: object, _metadata: object) -> object:
        steps["parse"] += 1
        return object()

    def signature(_tokens: object, _jwks: object) -> SignatureCheckedUntrustedOidcPayload:
        steps["signature"] += 1
        return SignatureCheckedUntrustedOidcPayload(
            algorithm="RS256",
            kid="synthetic-kid",
            payload=payload,
        )

    real_inspect = verification_module.inspect_untrusted_cern_application_role

    def inspect(*args: object, **kwargs: object) -> object:
        steps["inspect"] += 1
        return real_inspect(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(pipeline._fetcher, "fetch", fetched)
    monkeypatch.setattr(verification_module, "parse_cern_public_jwks", parsed)
    monkeypatch.setattr(verification_module, "verify_untrusted_oidc_jws_signature", signature)
    monkeypatch.setattr(verification_module, "inspect_untrusted_cern_application_role", inspect)
    return pipeline, steps


def observe(pipeline: CernOidcVerificationPipeline, **kwargs: object) -> object:
    inputs: dict[str, object] = {
        "expected_client_id": CLIENT,
        "expected_nonce": NONCE,
        "expected_role": ROLE,
        "now": NOW,
    }
    inputs.update(kwargs)
    return pipeline.observe_role(tokens(), metadata(), **inputs)  # type: ignore[arg-type]


def test_no_caller_provided_signature_or_claims_result() -> None:
    pipeline = CernOidcVerificationPipeline()
    assert "checked" not in pipeline.observe_role.__code__.co_varnames
    assert "role_claims" not in pipeline.observe_role.__code__.co_varnames


@pytest.mark.parametrize(
    "changes",
    [
        {"expected_client_id": "other-client"},
        {"expected_nonce": "wrong"},
        {"now": 0},
        {"now": True},
        {"now": "2026"},
    ],
)
def test_bad_identity_binding_rejected(
    monkeypatch: pytest.MonkeyPatch, changes: dict[str, object]
) -> None:
    pipeline, steps = prepared(monkeypatch, signed_claims())
    with pytest.raises(OidcVerificationError):
        observe(pipeline, **changes)
    assert steps["inspect"] == 0


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://attacker.invalid"},
        {"aud": "other-client"},
        {"nonce": "wrong-nonce"},
        {"exp": NOW - 100},
        {"at_hash": "wrong"},
        {"c_hash": "unsupported"},
        {"s_hash": "unsupported"},
    ],
)
def test_signed_but_invalid_oidc_claims_never_inspected(
    monkeypatch: pytest.MonkeyPatch, claims: dict[str, object]
) -> None:
    pipeline, steps = prepared(monkeypatch, signed_claims(**claims))
    with pytest.raises(OidcVerificationError, match="verification was rejected"):
        observe(pipeline)
    assert steps["fetch"] == 1
    assert steps["signature"] == 1
    assert steps["inspect"] == 0


@pytest.mark.parametrize(
    "claims",
    [
        {"resource_access": {CLIENT: {"roles": [ROLE, ROLE]}}},
        {"resource_access": {CLIENT: {"roles": [ROLE]}}, "cern_roles": []},
        {"cern_roles_missing_mfa": [ROLE]},
        {"cern_roles_missing_loa": [ROLE]},
    ],
)
def test_role_structure_rejection_is_sanitized(
    monkeypatch: pytest.MonkeyPatch, claims: dict[str, object]
) -> None:
    pipeline, steps = prepared(monkeypatch, signed_claims(**claims))
    with pytest.raises(OidcVerificationError, match="role observation was rejected") as err:
        observe(pipeline)
    assert steps == {"fetch": 1, "parse": 1, "signature": 1, "inspect": 1}
    assert TOKEN not in repr(err.value)
    assert ROLE not in str(err.value)


def test_wrong_access_token_cannot_satisfy_at_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline, steps = prepared(monkeypatch, signed_claims())
    with pytest.raises(OidcVerificationError):
        pipeline.observe_role(
            tokens(access_token="swapped-token"),
            metadata(),
            expected_client_id=CLIENT,
            expected_nonce=NONCE,
            expected_role=ROLE,
            now=NOW,
        )
    assert steps["inspect"] == 0


def test_invalid_signature_stops_before_claims_and_roles(monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline, steps = prepared(monkeypatch, signed_claims())

    def reject_signature(*_args: object) -> None:
        raise OidcJwsError("synthetic signature failure")

    monkeypatch.setattr(
        verification_module, "verify_untrusted_oidc_jws_signature", reject_signature
    )
    with pytest.raises(OidcVerificationError, match="verification was rejected"):
        observe(pipeline)
    assert steps["fetch"] == 1
    assert steps["inspect"] == 0


def test_offline_pipeline_does_not_create_network_or_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline, steps = prepared(monkeypatch, signed_claims())

    def reject_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Unexpected socket access")

    monkeypatch.setattr(socket, "create_connection", reject_network)
    monkeypatch.setattr(socket.socket, "connect", reject_network)
    result = observe(pipeline)
    assert result.status == "claimed"
    assert result.authorization == "not_implemented"
    assert result.login == "not_implemented"
    assert not hasattr(result, "authenticated")
    assert not hasattr(result, "session")
    assert not hasattr(result, "permissions")
    assert steps == {"fetch": 1, "parse": 1, "signature": 1, "inspect": 1}
