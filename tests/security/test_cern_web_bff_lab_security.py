"""Security regressions for the isolated, non-authoritative mock CERN BFF lab."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi.testclient import TestClient

from prototypes.cern_web_bff_lab import (
    ATTEMPT_COOKIE,
    ATTEMPT_TTL,
    BASE_URL,
    CALLBACK,
    CLIENT_ID,
    ISSUER,
    create_lab_app,
    verify_synthetic_token,
)


def client() -> TestClient:
    return TestClient(create_lab_app(), base_url=BASE_URL, follow_redirects=False)


def begin(browser: TestClient) -> tuple[str, str, str]:
    started = browser.get("/lab/start")
    assert started.status_code == 303
    assert "secure" in started.headers["set-cookie"].lower()
    assert "httponly" in started.headers["set-cookie"].lower()
    assert "samesite=lax" in started.headers["set-cookie"].lower()
    assert "__Host-" in started.headers["set-cookie"]
    uri = started.headers["location"]
    authorization = browser.get(uri)
    assert authorization.status_code == 200
    assert "NOT CERN" in authorization.text
    match = re.search(r"name='ticket' value='([A-Za-z0-9_-]+)'", authorization.text)
    assert match is not None
    approved = browser.get("/mock/approve", params={"ticket": match.group(1)})
    assert approved.status_code == 303
    callback = approved.headers["location"]
    return uri, callback, match.group(1)


def _signed(lab: object, claims: dict[str, object]) -> str:
    header = {"alg": "RS256", "kid": "mock-ephemeral", "typ": "JWT"}

    def encode(obj: dict[str, object]) -> str:
        return (
            base64.urlsafe_b64encode(
                json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
            )
            .rstrip(b"=")
            .decode()
        )

    signing = f"{encode(header)}.{encode(claims)}"
    sig = lab.private_key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


def test_browser_flow_completes_only_synthetic_exchange() -> None:
    with client() as browser:
        landing = browser.get("/lab")
        assert landing.status_code == 200
        assert "No CERN SSO" in landing.text
        _, callback, _ = begin(browser)
        finished = browser.get(callback)
        assert finished.status_code == 200
        assert "Synthetic code exchange" in finished.text
        assert "NO CERN identity" in finished.text
        assert "Max-Age=0" in finished.headers["set-cookie"]
        assert "id_token" not in finished.text
        assert browser.cookies.get(ATTEMPT_COOKIE) is None
        assert browser.get("/lab/status").json() == {
            "provider": "synthetic_mock_only",
            "asca_identity": "not_configured",
            "authorization": "disabled",
            "session": "disabled",
            "external_access": "disabled",
        }


def test_replayed_callback_and_approve_ticket_fail() -> None:
    with client() as browser:
        _, callback, ticket = begin(browser)
        assert browser.get(callback).status_code == 200
        assert browser.get(callback).status_code == 400
        assert browser.get("/mock/approve", params={"ticket": ticket}).status_code == 400


def test_caller_without_original_browser_cookie_is_rejected() -> None:
    app = create_lab_app()
    with TestClient(app, base_url=BASE_URL, follow_redirects=False) as first:
        _, callback, _ = begin(first)
        with TestClient(app, base_url=BASE_URL, follow_redirects=False) as second:
            assert second.get(callback).status_code == 400
        assert first.get(callback).status_code == 200


@pytest.mark.parametrize(
    "name,value", [("state", "wrong"), ("code", "wrong"), ("iss", "https://wrong.invalid")]
)
def test_callback_tampering_fails_closed(name: str, value: str) -> None:
    with client() as browser:
        _, callback, _ = begin(browser)
        parsed = urlparse(callback)
        params = {key: vals[0] for key, vals in parse_qs(parsed.query).items()}
        params[name] = value
        assert browser.get(parsed.path, params=params).status_code == 400
        assert browser.get("/lab/status").json()["authorization"] == "disabled"


def test_attempt_expiration_is_rejected() -> None:
    app = create_lab_app()
    with TestClient(app, base_url=BASE_URL, follow_redirects=False) as browser:
        _, callback, _ = begin(browser)
        lab = app.state.mock_lab
        with lab.lock:
            state = next(iter(lab.attempts))
            lab.attempts[state] = replace(
                lab.attempts[state], created=time.monotonic() - ATTEMPT_TTL - 1
            )
        assert browser.get(callback).status_code == 400


def test_wrong_pkce_verifier_consumes_mock_code() -> None:
    with client() as browser:
        _, callback, _ = begin(browser)
        code = parse_qs(urlparse(callback).query)["code"][0]
        response = browser.post(
            "/mock/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": CLIENT_ID,
                "redirect_uri": CALLBACK,
                "code_verifier": "A" * 43,
            },
        )
        assert response.status_code == 400
        assert response.json() == {"error": "invalid_grant"}
        assert browser.get(callback).status_code == 400


def test_wrong_browser_binding_and_duplicate_cookie_rejected() -> None:
    with client() as browser:
        _, callback, _ = begin(browser)
        original = browser.cookies.get(ATTEMPT_COOKIE)
        assert original is not None
        assert (
            browser.get(callback, headers={"cookie": f"{ATTEMPT_COOKIE}={'A' * 43}"}).status_code
            == 400
        )
        assert (
            browser.get(
                callback,
                headers={"cookie": (f"{ATTEMPT_COOKIE}={original}; {ATTEMPT_COOKIE}={original}")},
            ).status_code
            == 400
        )
        # Failed callbacks delete the browser cookie, but do not consume a different binding.
        assert (
            browser.get(callback, headers={"cookie": f"{ATTEMPT_COOKIE}={original}"}).status_code
            == 200
        )


def test_synthetic_id_token_signature_and_nonce_are_verified() -> None:
    app = create_lab_app()
    lab = app.state.mock_lab
    verifier = "V" * 48
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    ticket = lab.create_authorization("S" * 43, "N" * 43, challenge)
    code, _ = lab.approve(ticket)
    token = lab.redeem(code, verifier)
    verify_synthetic_token(token, "N" * 43, lab.private_key.public_key())
    with pytest.raises(ValueError):
        verify_synthetic_token(token, "Z" * 43, lab.private_key.public_key())
    segments = token.split(".")
    replacement = "A" if segments[1][-1] != "A" else "B"
    tampered = f"{segments[0]}.{segments[1][:-1]}{replacement}.{segments[2]}"
    with pytest.raises(ValueError):
        verify_synthetic_token(tampered, "N" * 43, lab.private_key.public_key())
    with pytest.raises(ValueError):
        verify_synthetic_token(
            "none." + segments[1] + ".none", "N" * 43, lab.private_key.public_key()
        )


@pytest.mark.parametrize(
    "change",
    [
        {"iss": "https://auth.cern.ch/auth/realms/cern"},
        {"aud": "real-cern-client"},
        {"nonce": "wrong"},
        {"sub": "real-person"},
        {"exp": 0},
        {"iat": 0},
        {"extra": "unexpected"},
    ],
)
def test_synthetic_id_token_rejects_forged_claims(change: dict[str, object]) -> None:
    lab = create_lab_app().state.mock_lab
    now = int(time.time())
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "synthetic-lab-user",
        "nonce": "N" * 43,
        "iat": now,
        "exp": now + 100,
    }
    claims.update(change)
    token = _signed(lab, claims)
    with pytest.raises(ValueError):
        verify_synthetic_token(token, "N" * 43, lab.private_key.public_key())


def test_non_https_and_other_hostname_are_rejected() -> None:
    app = create_lab_app()
    with TestClient(app, base_url="http://localhost:8443") as browser:
        assert browser.get("/lab").status_code == 403
        assert browser.get("/lab/start").status_code == 403
        assert browser.get("/lab/status").status_code == 403
    with TestClient(app, base_url="https://example.org") as browser:
        assert browser.get("/lab").status_code in (400, 403)


def test_invalid_authorization_params_and_duplicate_keys_are_rejected() -> None:
    with client() as browser:
        uri, _, _ = begin(browser)
        bad = uri + "&client_id=duplicate"
        assert browser.get(bad).status_code == 400
        assert browser.get("/mock/authorize").status_code == 400


def test_no_production_api_mount_or_live_cern_configuration() -> None:
    repo = Path(__file__).resolve().parents[2]
    source = (repo / "prototypes/cern_web_bff_lab.py").read_text(encoding="utf-8")
    assert "https://localhost:8443" in source
    assert "SYNTHETIC ONLY" in source
    assert 'host="127.0.0.1"' in source
    for source_path in (repo / "src/asca/api").glob("*.py"):
        assert "cern_web_bff_lab" not in source_path.read_text(encoding="utf-8")


def test_state_consumption_is_atomic_in_one_process() -> None:
    lab = create_lab_app().state.mock_lab
    state, _, _, binding = lab.start()

    def consume(_index: int) -> bool:
        try:
            lab.consume_attempt(state, binding)
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(consume, range(8)))
    assert outcomes.count(True) == 1


def test_mock_code_consumption_is_atomic_in_one_process() -> None:
    lab = create_lab_app().state.mock_lab
    verifier = "V" * 48
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    ticket = lab.create_authorization("S" * 43, "N" * 43, challenge)
    code, _ = lab.approve(ticket)

    def redeem(_index: int) -> bool:
        try:
            lab.redeem(code, verifier)
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(redeem, range(8)))
    assert outcomes.count(True) == 1


def test_signed_but_mismatched_token_fails_after_code_consumption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_lab_app()
    lab = app.state.mock_lab
    original_redeem = lab.redeem

    def forged_redeem(code: str, verifier: str) -> str:
        original_redeem(code, verifier)
        issued = int(time.time())
        return _signed(
            lab,
            {
                "iss": ISSUER,
                "aud": "wrong-client",
                "sub": "synthetic-lab-user",
                "nonce": "N" * 43,
                "iat": issued,
                "exp": issued + 100,
            },
        )

    monkeypatch.setattr(lab, "redeem", forged_redeem)
    with TestClient(app, base_url=BASE_URL, follow_redirects=False) as browser:
        _, callback, _ = begin(browser)
        assert browser.get(callback).status_code == 400
        assert browser.get(callback).status_code == 400


def test_oversized_mock_token_request_is_rejected() -> None:
    with client() as browser:
        response = browser.post(
            "/mock/token",
            data={"code_verifier": "A" * 8000},
        )
        assert response.status_code == 400
        assert response.json() == {"error": "invalid_grant"}
