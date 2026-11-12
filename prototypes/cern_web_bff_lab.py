"""Isolated HTTPS loopback mock-OIDC BFF lab; NOT CERN authentication.

This file is deliberately outside src/asca and is never mounted in the ASCA API.
Its local mock provider does not identify real people and cannot grant access.
Do not substitute the CERN issuer or real OIDC credentials into this prototype.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlencode

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware

BASE_URL = "https://localhost:8443"
ISSUER = f"{BASE_URL}/mock"
CLIENT_ID = "asca-web-lab-synthetic"
CALLBACK = f"{BASE_URL}/lab/callback"
ATTEMPT_COOKIE = "__Host-asca-mock-bff-attempt"
ATTEMPT_TTL = 180
MAX_PENDING = 128
_TOKEN = re.compile(r"[A-Za-z0-9_-]{22,128}\Z", re.ASCII)
_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}\Z", re.ASCII)
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer"}


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(segment: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", segment, re.ASCII):
        raise ValueError("Invalid synthetic token")
    decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if _b64(decoded) != segment:
        raise ValueError("Invalid synthetic token")
    return decoded


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Invalid synthetic token")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("Invalid synthetic token")


def _strict_json(raw: bytes) -> dict[str, object]:
    document = json.loads(
        raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_reject_constant
    )
    if type(document) is not dict:
        raise ValueError("Invalid synthetic token")
    return document


@dataclass(frozen=True, slots=True)
class Attempt:
    binding_digest: bytes
    nonce: str
    verifier: str
    created: float


@dataclass(frozen=True, slots=True)
class Authorization:
    state: str
    nonce: str
    challenge: str
    created: float


@dataclass(frozen=True, slots=True)
class MockCode:
    nonce: str
    challenge: str
    created: float


class MemoryLab:
    """Bounded, single-process mock stores. NOT shared or durable storage."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.attempts: dict[str, Attempt] = {}
        self.authorizations: dict[str, Authorization] = {}
        self.codes: dict[str, MockCode] = {}
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _prune(self, now: float) -> None:
        for mapping in (self.attempts, self.authorizations, self.codes):
            for key, value in list(mapping.items()):
                if now - value.created >= ATTEMPT_TTL:
                    del mapping[key]

    def start(self) -> tuple[str, str, str, str]:
        with self.lock:
            now = time.monotonic()
            self._prune(now)
            if len(self.attempts) >= MAX_PENDING:
                raise ValueError("Lab capacity exceeded")
            state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            verifier, binding = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
            self.attempts[state] = Attempt(
                hashlib.sha256(binding.encode("ascii")).digest(), nonce, verifier, now
            )
            return state, nonce, verifier, binding

    def consume_attempt(self, state: str, binding: str) -> Attempt:
        with self.lock:
            attempt = self.attempts.get(state)
            if attempt is None or time.monotonic() - attempt.created >= ATTEMPT_TTL:
                raise ValueError("Invalid synthetic transaction")
            digest = hashlib.sha256(binding.encode("ascii")).digest()
            if not hmac.compare_digest(attempt.binding_digest, digest):
                raise ValueError("Invalid synthetic transaction")
            del self.attempts[state]  # Single-use even if mock exchange fails.
            return attempt

    def create_authorization(self, state: str, nonce: str, challenge: str) -> str:
        with self.lock:
            now = time.monotonic()
            self._prune(now)
            if len(self.authorizations) >= MAX_PENDING:
                raise ValueError("Lab capacity exceeded")
            ticket = secrets.token_urlsafe(32)
            self.authorizations[ticket] = Authorization(state, nonce, challenge, now)
            return ticket

    def approve(self, ticket: str) -> tuple[str, str]:
        with self.lock:
            transaction = self.authorizations.pop(ticket, None)
            if transaction is None or time.monotonic() - transaction.created >= ATTEMPT_TTL:
                raise ValueError("Invalid mock authorization")
            if len(self.codes) >= MAX_PENDING:
                raise ValueError("Lab capacity exceeded")
            code = secrets.token_urlsafe(32)
            self.codes[code] = MockCode(transaction.nonce, transaction.challenge, time.monotonic())
            return code, transaction.state

    def redeem(self, code: str, verifier: str) -> str:
        with self.lock:
            record = self.codes.pop(code, None)
            if record is None or time.monotonic() - record.created >= ATTEMPT_TTL:
                raise ValueError("Invalid mock authorization code")
            if not hmac.compare_digest(
                _b64(hashlib.sha256(verifier.encode("ascii")).digest()), record.challenge
            ):
                raise ValueError("Mock PKCE verification failed")
            nonce = record.nonce
        issued = int(time.time())
        header = {"alg": "RS256", "kid": "mock-ephemeral", "typ": "JWT"}
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "synthetic-lab-user",
            "nonce": nonce,
            "iat": issued,
            "exp": issued + 120,
        }
        signing_input = ".".join(
            _b64(json.dumps(item, separators=(",", ":"), sort_keys=True).encode("utf-8"))
            for item in (header, claims)
        )
        signature = self.private_key.sign(
            signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )
        return f"{signing_input}.{_b64(signature)}"


def verify_synthetic_token(token: object, nonce: str, public_key: rsa.RSAPublicKey) -> None:
    """Validate the local synthetic issuer only; never authenticate a CERN identity."""
    if type(token) is not str or len(token) > 8192 or len(token) < 30:
        raise ValueError("Invalid synthetic token")
    pieces = token.split(".")
    if len(pieces) != 3:
        raise ValueError("Invalid synthetic token")
    try:
        header, claims = _strict_json(_decode(pieces[0])), _strict_json(_decode(pieces[1]))
        signature = _decode(pieces[2])
        if header != {"alg": "RS256", "kid": "mock-ephemeral", "typ": "JWT"}:
            raise ValueError("Invalid synthetic token")
        public_key.verify(
            signature, ".".join(pieces[:2]).encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
        )
        now = int(time.time())
        if (
            set(claims) != {"iss", "aud", "sub", "nonce", "iat", "exp"}
            or claims["iss"] != ISSUER
            or claims["aud"] != CLIENT_ID
            or claims["sub"] != "synthetic-lab-user"
            or type(claims["nonce"]) is not str
            or not hmac.compare_digest(claims["nonce"], nonce)
            or type(claims["iat"]) is not int
            or type(claims["exp"]) is not int
            or not now - 30 <= claims["iat"] <= now + 30
            or not now < claims["exp"] <= claims["iat"] + 120
        ):
            raise ValueError("Invalid synthetic token")
    except (ValueError, TypeError, UnicodeError, InvalidSignature, OverflowError):
        raise ValueError("Invalid synthetic token") from None


def _cookie(headers: list[tuple[bytes, bytes]]) -> str:
    raw = [val for key, val in headers if key.lower() == b"cookie"]
    if len(raw) != 1 or len(raw[0]) > 4096:
        raise ValueError("Invalid mock browser binding")
    try:
        value = raw[0].decode("ascii")
    except UnicodeError:
        raise ValueError("Invalid mock browser binding") from None
    found: str | None = None
    for part in value.split(";"):
        key, separator, candidate = part.strip().partition("=")
        if key == ATTEMPT_COOKIE:
            if not separator or found is not None or _TOKEN.fullmatch(candidate) is None:
                raise ValueError("Invalid mock browser binding")
            found = candidate
    if found is None:
        raise ValueError("Invalid mock browser binding")
    return found


def _local_https(request: Request) -> bool:
    return request.url.scheme == "https" and request.url.hostname == "localhost"


def _html_response(body: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        "<!doctype html><html lang='en'><meta charset='utf-8'><title>ASCA Mock OIDC Lab"
        "</title><main><h1>ASCA isolated OIDC lab — SYNTHETIC ONLY</h1>"
        f"<p>{html.escape(body)}</p></main></html>",
        status_code=status_code,
        headers={**_NO_STORE, "Content-Security-Policy": "default-src 'none'"},
    )


def create_lab_app() -> FastAPI:
    """Construct a standalone lab application; never mount into ASCA API."""
    lab = MemoryLab()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "localhost:8443"])
    app.state.mock_lab = lab

    @app.get("/lab")
    def index(request: Request) -> HTMLResponse:
        if not _local_https(request):
            return _html_response("HTTPS loopback only", 403)
        return HTMLResponse(
            "<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<title>ASCA Mock OIDC Lab</title><main>"
            "<h1>ASCA isolated BFF lab</h1>"
            "<p>MOCK PROVIDER. No CERN SSO. No real identity, login or permissions.</p>"
            "<a href='/lab/start'>Run synthetic authorization-code + PKCE test</a>"
            "</main></html>",
            headers={**_NO_STORE, "Content-Security-Policy": "default-src 'none'"},
        )

    @app.get("/lab/status")
    def status(request: Request) -> JSONResponse:
        if not _local_https(request):
            return JSONResponse({"status": "unavailable"}, status_code=403)
        return JSONResponse(
            {
                "provider": "synthetic_mock_only",
                "asca_identity": "not_configured",
                "authorization": "disabled",
                "session": "disabled",
                "external_access": "disabled",
            },
            headers=_NO_STORE,
        )

    @app.get("/lab/start")
    def start(request: Request) -> Response:
        if not _local_https(request):
            return _html_response("HTTPS loopback only", 403)
        try:
            state, nonce, verifier, binding = lab.start()
        except ValueError:
            return _html_response("Mock lab temporarily unavailable", 503)
        challenge = _b64(hashlib.sha256(verifier.encode("ascii")).digest())
        params = urlencode(
            {
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": CALLBACK,
                "scope": "openid",
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        response = RedirectResponse(f"/mock/authorize?{params}", status_code=303, headers=_NO_STORE)
        response.set_cookie(
            ATTEMPT_COOKIE,
            binding,
            max_age=ATTEMPT_TTL,
            secure=True,
            httponly=True,
            samesite="lax",
            path="/",
        )
        return response

    @app.get("/mock/authorize")
    def authorize(request: Request) -> HTMLResponse:
        if not _local_https(request):
            return _html_response("HTTPS loopback only", 403)
        params = request.query_params
        try:
            if (
                len(params) != 8
                or len(set(params)) != 8
                or params.get("response_type") != "code"
                or params.get("client_id") != CLIENT_ID
                or params.get("redirect_uri") != CALLBACK
                or params.get("scope") != "openid"
                or params.get("code_challenge_method") != "S256"
                or _TOKEN.fullmatch(params.get("state", "")) is None
                or _TOKEN.fullmatch(params.get("nonce", "")) is None
                or _CHALLENGE.fullmatch(params.get("code_challenge", "")) is None
            ):
                raise ValueError("Invalid mock authorization request")
            ticket = lab.create_authorization(
                params["state"], params["nonce"], params["code_challenge"]
            )
        except (ValueError, TypeError):
            return _html_response("Invalid synthetic request", 400)
        return HTMLResponse(
            "<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<title>Mock identity provider</title><main>"
            "<h1>Mock identity provider — NOT CERN</h1>"
            "<p>No password or real credentials are required or accepted.</p>"
            f"<form action='/mock/approve' method='get'><input type='hidden' name='ticket'"
            f" value='{ticket}'><button type='submit'>Approve synthetic login test</button></form>"
            "</main></html>",
            headers={
                **_NO_STORE,
                "Content-Security-Policy": "default-src 'none'; form-action 'self'",
            },
        )

    @app.get("/mock/approve")
    def approve(request: Request) -> Response:
        if not _local_https(request):
            return _html_response("HTTPS loopback only", 403)
        ticket = request.query_params.get("ticket", "")
        if len(request.query_params) != 1 or _TOKEN.fullmatch(ticket) is None:
            return _html_response("Invalid synthetic request", 400)
        try:
            code, state = lab.approve(ticket)
        except ValueError:
            return _html_response("Invalid synthetic request", 400)
        return RedirectResponse(
            "/lab/callback?" + urlencode({"code": code, "state": state, "iss": ISSUER}),
            status_code=303,
            headers=_NO_STORE,
        )

    @app.post("/mock/token")
    async def token_endpoint(request: Request) -> JSONResponse:
        if not _local_https(request):
            return JSONResponse({"error": "invalid_request"}, status_code=403)
        try:
            if request.headers.get("content-type", "").split(";", 1)[0] != (
                "application/x-www-form-urlencoded"
            ):
                raise ValueError("Invalid mock token request")
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 4096:
                    raise ValueError("Invalid mock token request")
            decoded = parse_qs(body.decode("ascii"), strict_parsing=True, max_num_fields=6)
            if set(decoded) != {
                "grant_type",
                "code",
                "client_id",
                "redirect_uri",
                "code_verifier",
            } or any(len(val) != 1 for val in decoded.values()):
                raise ValueError("Invalid mock token request")
            values = {key: val[0] for key, val in decoded.items()}
            if (
                values["grant_type"] != "authorization_code"
                or values["client_id"] != CLIENT_ID
                or values["redirect_uri"] != CALLBACK
                or _TOKEN.fullmatch(values["code"]) is None
                or _TOKEN.fullmatch(values["code_verifier"]) is None
            ):
                raise ValueError("Invalid mock token request")
            token = lab.redeem(values["code"], values["code_verifier"])
            return JSONResponse(
                {"id_token": token, "token_type": "Bearer", "expires_in": 120}, headers=_NO_STORE
            )
        except (ValueError, UnicodeError):
            return JSONResponse({"error": "invalid_grant"}, status_code=400, headers=_NO_STORE)

    @app.get("/lab/callback")
    async def callback(request: Request) -> HTMLResponse:
        if not _local_https(request):
            return _html_response("HTTPS loopback only", 403)
        response = _html_response("Synthetic OIDC transaction rejected", 400)
        response.delete_cookie(ATTEMPT_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
        params = request.query_params
        if (
            len(params) != 3
            or len(set(params)) != 3
            or _TOKEN.fullmatch(params.get("state", "")) is None
            or _TOKEN.fullmatch(params.get("code", "")) is None
            or params.get("iss") != ISSUER
        ):
            return response
        try:
            browser = _cookie(request.scope["headers"])
            attempt = lab.consume_attempt(params["state"], browser)
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url=BASE_URL,
                follow_redirects=False,
                timeout=5.0,
            ) as client:
                exchange = await client.post(
                    "/mock/token",
                    data={
                        "grant_type": "authorization_code",
                        "code": params["code"],
                        "client_id": CLIENT_ID,
                        "redirect_uri": CALLBACK,
                        "code_verifier": attempt.verifier,
                    },
                )
            if exchange.status_code != 200 or len(exchange.content) > 8192:
                raise ValueError("Invalid synthetic exchange")
            doc = exchange.json()
            if (
                type(doc) is not dict
                or set(doc) != {"id_token", "token_type", "expires_in"}
                or doc["token_type"] != "Bearer"
                or doc["expires_in"] != 120
            ):
                raise ValueError("Invalid synthetic exchange")
            verify_synthetic_token(doc["id_token"], attempt.nonce, lab.private_key.public_key())
        except (ValueError, UnicodeError, TypeError, httpx.HTTPError):
            return response
        success = _html_response(
            "Synthetic code exchange, PKCE, browser state and signed nonce verified. "
            "NO CERN identity, ASCA login, session or permissions were created."
        )
        success.delete_cookie(ATTEMPT_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
        return success

    return app


def main() -> None:
    """Explicit local TLS launch; avoid proxy, public bind and access logs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certfile", type=Path, required=True)
    parser.add_argument("--keyfile", type=Path, required=True)
    args = parser.parse_args()
    if not args.certfile.is_file() or not args.keyfile.is_file():
        parser.error("Use a local HTTPS development certificate and key")
    import uvicorn

    print("SYNTHETIC LAB ONLY: https://localhost:8443/lab — no CERN login or access")
    uvicorn.run(
        create_lab_app(),
        host="127.0.0.1",
        port=8443,
        access_log=False,
        ssl_certfile=str(args.certfile),
        ssl_keyfile=str(args.keyfile),
    )


if __name__ == "__main__":
    main()
