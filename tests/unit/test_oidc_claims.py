"""Offline OIDC claims tests with synthetic signature-checked payload containers."""

import json
from dataclasses import FrozenInstanceError

import pytest

from asca.application.oidc_claims import validate_untrusted_oidc_id_token_claims
from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.domain.identity import VerifiedIdentity
from asca.domain.oidc_claims import ClaimsCheckedUntrustedOidcPayload, OidcClaimsError
from asca.domain.oidc_jws import SignatureCheckedUntrustedOidcPayload

NOW = 1_800_000_000
CLIENT_ID = "test-cern-client"
NONCE = "syntheticNonce0123456789abcdefghij_123456"


def claims(**changes: object) -> dict[str, object]:
    document: dict[str, object] = {
        "iss": CERN_OIDC_ISSUER,
        "sub": "synthetic-subject-123",
        "aud": CLIENT_ID,
        "exp": NOW + 300,
        "iat": NOW - 20,
        "nonce": NONCE,
    }
    document.update(changes)
    return document


def checked(
    document: object = None, *, raw: bytes | None = None
) -> SignatureCheckedUntrustedOidcPayload:
    if raw is None:
        raw = json.dumps(document if document is not None else claims()).encode("utf-8")
    return SignatureCheckedUntrustedOidcPayload(algorithm="RS256", kid="synthetic", payload=raw)


def validate(document: object = None, **kwargs: object) -> ClaimsCheckedUntrustedOidcPayload:
    opts: dict[str, object] = {
        "expected_client_id": CLIENT_ID,
        "expected_nonce": NONCE,
        "now": NOW,
    }
    opts.update(kwargs)
    return validate_untrusted_oidc_id_token_claims(
        checked(document),
        **opts,  # type: ignore[arg-type]
    )


def test_valid_claims_checked_but_never_authenticated() -> None:
    result = validate()
    assert isinstance(result, ClaimsCheckedUntrustedOidcPayload)
    assert not isinstance(result, VerifiedIdentity)
    assert result.issuer == CERN_OIDC_ISSUER
    assert result.subject == "synthetic-subject-123"
    assert result.audiences == (CLIENT_ID,)
    assert result.authorized_party is None
    assert result.nonce == NONCE
    assert result.issued_at == NOW - 20
    assert result.expires_at == NOW + 300
    assert result.not_before is None
    assert result.algorithm == "RS256"
    assert result.kid == "synthetic"
    for name in ("identity", "permissions", "session", "verified_jwks", "roles"):
        assert not hasattr(result, name)
    for sensitive in (NONCE, CLIENT_ID, "synthetic-subject-123", CERN_OIDC_ISSUER):
        assert sensitive not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.nonce = "other"  # type: ignore[misc]


def test_single_audience_list_and_matching_azp_allowed() -> None:
    result = validate(claims(aud=[CLIENT_ID], azp=CLIENT_ID))
    assert result.audiences == (CLIENT_ID,)
    assert result.authorized_party == CLIENT_ID


def test_multiple_audiences_require_explicit_allowlist_and_azp() -> None:
    doc = claims(aud=[CLIENT_ID, "https://internal-service.example"], azp=CLIENT_ID)
    with pytest.raises(OidcClaimsError, match="audience"):
        validate(doc)
    result = validate(doc, trusted_additional_audiences=("https://internal-service.example",))
    assert result.audiences == (CLIENT_ID, "https://internal-service.example")
    assert result.authorized_party == CLIENT_ID


def test_optional_nbf_and_auth_time_are_supported() -> None:
    result = validate(claims(nbf=NOW - 10, auth_time=NOW - 200, email="not-authority@example"))
    assert result.not_before == NOW - 10
    assert not hasattr(result, "email")
    assert not hasattr(result, "auth_time")


def test_no_authorization_from_unknown_extensions() -> None:
    result = validate(claims(groups=["cern-admin"], roles=["root"], is_admin=True, acr="2"))
    for name in ("groups", "roles", "is_admin", "acr"):
        assert not hasattr(result, name)


@pytest.mark.parametrize("seconds", [0, 1, 60, 120])
def test_allowed_clock_skew_configuration(seconds: int) -> None:
    assert validate(clock_skew_seconds=seconds).subject == "synthetic-subject-123"


@pytest.mark.parametrize("seconds", [320, 3600, 86400])
def test_allowed_max_lifetime_configuration(seconds: int) -> None:
    assert validate(max_token_lifetime_seconds=seconds).subject == "synthetic-subject-123"


def test_expires_at_exact_now_with_zero_skew_is_rejected() -> None:
    with pytest.raises(OidcClaimsError, match="expired"):
        validate(claims(exp=NOW, iat=NOW - 100), clock_skew_seconds=0)


def test_small_expiry_grace_is_supported_when_configured() -> None:
    assert validate(claims(exp=NOW - 1, iat=NOW - 100), clock_skew_seconds=60).expires_at == NOW - 1


def test_exact_expiry_grace_boundary_is_rejected() -> None:
    with pytest.raises(OidcClaimsError, match="expired"):
        validate(claims(exp=NOW - 60, iat=NOW - 120), clock_skew_seconds=60)


def test_future_iat_skew_boundary_is_supported() -> None:
    actual = validate(claims(iat=NOW + 60, exp=NOW + 300), clock_skew_seconds=60)
    assert actual.issued_at == NOW + 60


def test_future_nbf_skew_boundary_is_supported() -> None:
    assert validate(claims(nbf=NOW + 60), clock_skew_seconds=60).not_before == NOW + 60


def test_explicit_lifetime_limit_is_enforced() -> None:
    with pytest.raises(OidcClaimsError, match="expired"):
        validate(claims(iat=NOW - 20, exp=NOW + 600), max_token_lifetime_seconds=300)


def test_valid_payload_is_not_bound_to_actual_jwks_or_user() -> None:
    # This manually constructed JWS result can be forged by any Python caller.
    data = checked()
    result = validate_untrusted_oidc_id_token_claims(
        data, expected_client_id=CLIENT_ID, expected_nonce=NONCE, now=NOW
    )
    assert not hasattr(result, "provenance_verified")
    assert not hasattr(result, "principal")
    assert not hasattr(result, "authenticated")


@pytest.mark.parametrize("algorithm", ["RS256", "PS256", "ES256"])
def test_real_ephemeral_jws_signature_can_feed_claims_checker(algorithm: str) -> None:
    """Integrate the genuine cryptographic verifier without trusting CERN source."""
    import base64

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

    from asca.application.oidc_jwks import parse_cern_public_jwks
    from asca.domain.oidc_discovery import OidcProviderMetadata
    from asca.infrastructure.oidc_jws import verify_untrusted_oidc_jws_signature

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    if algorithm == "ES256":
        private: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey = ec.generate_private_key(
            ec.SECP256R1()
        )
        numbers = private.public_key().public_numbers()
        jwk = {
            "kid": "integration-key",
            "use": "sig",
            "alg": algorithm,
            "kty": "EC",
            "crv": "P-256",
            "x": b64(numbers.x.to_bytes(32, "big")),
            "y": b64(numbers.y.to_bytes(32, "big")),
        }
    else:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private.public_key().public_numbers()
        jwk = {
            "kid": "integration-key",
            "use": "sig",
            "alg": algorithm,
            "kty": "RSA",
            "n": b64(numbers.n.to_bytes(256, "big")),
            "e": b64(numbers.e.to_bytes(3, "big")),
        }
    metadata = OidcProviderMetadata(
        issuer=CERN_OIDC_ISSUER,
        authorization_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/auth",
        token_endpoint=CERN_OIDC_ISSUER + "/protocol/openid-connect/token",
        jwks_uri=CERN_OIDC_ISSUER + "/protocol/openid-connect/certs",
        approved_id_token_algorithms=("RS256", "PS256", "ES256"),
        supports_authorization_code=True,
        supports_pkce_s256=True,
    )
    jwks = parse_cern_public_jwks(json.dumps({"keys": [jwk]}).encode("ascii"), metadata)
    protected = b64(json.dumps({"alg": algorithm, "kid": "integration-key"}).encode("ascii"))
    payload = b64(json.dumps(claims()).encode("ascii"))
    signed_data = (protected + "." + payload).encode("ascii")
    if isinstance(private, rsa.RSAPrivateKey):
        scheme = (
            padding.PKCS1v15()
            if algorithm == "RS256"
            else padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
        )
        signature = private.sign(signed_data, scheme, hashes.SHA256())
    else:
        encoded_der = private.sign(signed_data, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(encoded_der)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    signed_token = signed_data.decode("ascii") + "." + b64(signature)
    from asca.domain.oidc_token_response import ParsedUnverifiedOidcTokenResponse

    parsed = ParsedUnverifiedOidcTokenResponse(
        access_token="synthetic",
        id_token=signed_token,
        token_type="Bearer",
        expires_in=300,
        refresh_token=None,
        scope=None,
    )
    signature_checked = verify_untrusted_oidc_jws_signature(parsed, jwks)
    validated = validate_untrusted_oidc_id_token_claims(
        signature_checked, expected_client_id=CLIENT_ID, expected_nonce=NONCE, now=NOW
    )
    assert validated.subject == "synthetic-subject-123"
    assert not isinstance(validated, VerifiedIdentity)
    with pytest.raises(OidcClaimsError, match="nonce"):
        validate_untrusted_oidc_id_token_claims(
            signature_checked,
            expected_client_id=CLIENT_ID,
            expected_nonce="wrong_nonce_01234567890123456789",
            now=NOW,
        )
