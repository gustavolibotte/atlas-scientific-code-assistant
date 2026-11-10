"""Pinned CERN JWKS HTTPS retrieval, isolated from the production login flow.

The default transport verifies TLS, disables environment proxies and redirects,
and bounds the response bytes. An injected opener is for *offline tests only*.
No application route or startup hook invokes this class.
"""

from __future__ import annotations

import math
import ssl
from http.client import HTTPException
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    OpenerDirector,
    ProxyHandler,
    Request,
    build_opener,
)

from asca.application.oidc_discovery import CERN_OIDC_ISSUER
from asca.application.oidc_jwks import CERN_OIDC_JWKS_URI
from asca.domain.oidc_discovery import OidcProviderMetadata
from asca.domain.oidc_jwks_http import FetchedUnverifiedOidcJwks, OidcJwksHttpError

_MAX_JWKS_BYTES = 262_144
_APPROVED_ALGORITHMS = frozenset({"RS256", "PS256", "ES256"})
_JSON_MEDIA_TYPES = frozenset({"application/json", "application/jwk-set+json"})


class _RejectJwksRedirects(HTTPRedirectHandler):
    """Never follow a response to another origin or unreviewed CERN path."""

    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        del request, file_pointer, code, message, headers, new_url
        return None


def _validate_metadata(metadata: OidcProviderMetadata) -> None:
    """Check the declared trust anchor; do not trust a provider-supplied URL."""
    if (
        not isinstance(metadata, OidcProviderMetadata)
        or metadata.issuer != CERN_OIDC_ISSUER
        or metadata.jwks_uri != CERN_OIDC_JWKS_URI
        or metadata.supports_authorization_code is not True
        or metadata.supports_pkce_s256 is not True
        or not isinstance(metadata.approved_id_token_algorithms, tuple)
        or not metadata.approved_id_token_algorithms
        or any(
            not isinstance(alg, str) or alg not in _APPROVED_ALGORITHMS
            for alg in metadata.approved_id_token_algorithms
        )
        or len(set(metadata.approved_id_token_algorithms))
        != len(metadata.approved_id_token_algorithms)
    ):
        raise OidcJwksHttpError("OIDC JWKS fetch violates CERN metadata policy")


def _single_header(headers: Any, name: str) -> str | None:
    """Reject ambiguous, duplicated or control-bearing HTTP header values."""
    try:
        values = headers.get_all(name, [])
    except (AttributeError, TypeError, ValueError, KeyError):
        raise OidcJwksHttpError("Invalid OIDC JWKS HTTP response headers") from None
    if (
        not isinstance(values, list)
        or len(values) > 1
        or any(
            not isinstance(value, str)
            or not 1 <= len(value) <= 256
            or any(ord(char) < 32 or ord(char) >= 127 for char in value)
            for value in values
        )
    ):
        raise OidcJwksHttpError("Invalid OIDC JWKS HTTP response headers")
    return str(values[0]) if values else None


def _validate_headers(headers: Any) -> int | None:
    content_type = _single_header(headers, "Content-Type")
    if content_type is None:
        raise OidcJwksHttpError("Invalid OIDC JWKS HTTP content type")
    parts = [part.strip().lower() for part in content_type.split(";")]
    if (
        len(parts) not in (1, 2)
        or parts[0] not in _JSON_MEDIA_TYPES
        or (len(parts) == 2 and parts[1] != "charset=utf-8")
    ):
        raise OidcJwksHttpError("Invalid OIDC JWKS HTTP content type")

    content_encoding = _single_header(headers, "Content-Encoding")
    if content_encoding is not None and content_encoding.strip().lower() != "identity":
        raise OidcJwksHttpError("Compressed OIDC JWKS HTTP responses are not supported")

    content_length = _single_header(headers, "Content-Length")
    if content_length is not None and (
        not content_length.isascii()
        or len(content_length) > 10
        or not content_length.isdecimal()
        or not 0 < int(content_length) <= _MAX_JWKS_BYTES
    ):
        raise OidcJwksHttpError("Invalid OIDC JWKS HTTP content length")

    transfer_encoding = _single_header(headers, "Transfer-Encoding")
    if transfer_encoding is not None and (
        transfer_encoding.strip().lower() != "chunked" or content_length is not None
    ):
        raise OidcJwksHttpError("Ambiguous OIDC JWKS HTTP response framing")
    return int(content_length) if content_length is not None else None


class HttpsCernOidcJwksFetcher:
    """Fetch only the reviewed CERN JWKS URL when explicitly called.

    Injected openers bypass TLS guarantees and are intended *only* for tests.
    The configured socket timeout is not a strict end-to-end elapsed-time cap.
    This class is not wired into any production route or authentication flow.
    """

    def __init__(
        self,
        *,
        timeout_seconds: float = 5.0,
        opener: OpenerDirector | None = None,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (float, int))
            or not math.isfinite(timeout_seconds)
            or not 0.1 <= timeout_seconds <= 15.0
        ):
            raise ValueError("JWKS HTTPS timeout must be between 0.1 and 15 seconds")
        self._timeout = float(timeout_seconds)
        self._opener = opener or build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl.create_default_context()),
            _RejectJwksRedirects(),
        )

    def fetch(self, metadata: OidcProviderMetadata) -> FetchedUnverifiedOidcJwks:
        """Retrieve raw, unparsed JWKS bytes from the one pinned endpoint.

        Metadata must come from separately validated discovery. No JWT-provided
        URL, redirect, embedded JWK, user cookie or bearer token is consulted.
        """
        _validate_metadata(metadata)
        request = Request(
            CERN_OIDC_JWKS_URI,
            method="GET",
            headers={
                "Accept": "application/jwk-set+json, application/json",
                "Cache-Control": "no-store",
                "User-Agent": "ASCA-OIDC-jwks/1.0",
            },
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                if response.status != 200:
                    raise OidcJwksHttpError("OIDC JWKS HTTP response was rejected")
                declared_length = _validate_headers(response.headers)
                raw = response.read(_MAX_JWKS_BYTES + 1)
                if (
                    not isinstance(raw, bytes)
                    or not raw
                    or len(raw) > _MAX_JWKS_BYTES
                    or (declared_length is not None and len(raw) != declared_length)
                ):
                    raise OidcJwksHttpError("OIDC JWKS HTTP response was rejected")
                return FetchedUnverifiedOidcJwks(
                    body=raw,
                    source_url=CERN_OIDC_JWKS_URI,
                )
        except OidcJwksHttpError:
            raise
        except (HTTPError, URLError, HTTPException, TimeoutError, OSError, ValueError, TypeError):
            raise OidcJwksHttpError("OIDC JWKS HTTPS retrieval failed") from None
