"""Bounded, TLS-verified, no-redirect retrieval of public OIDC discovery JSON."""

from __future__ import annotations

import json
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    OpenerDirector,
    Request,
    build_opener,
)

from asca.application.oidc_discovery import OidcDiscoveryPolicy
from asca.domain.oidc_discovery import OidcDiscoveryError

_MAX_METADATA_BYTES = 262_144


class _NoRedirect(HTTPRedirectHandler):
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


def _unique_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OidcDiscoveryError("OIDC metadata contains duplicate JSON members")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    del value
    raise OidcDiscoveryError("OIDC metadata contains non-finite JSON numbers")


class HttpsOidcMetadataFetcher:
    """Only retrieves the one public discovery URL in the injected trust policy.

    No cookies, Authorization headers, client secrets, or redirects are used.
    An explicit timeout, response-size cap, and JSON duplicate-key rejection
    minimize exposure when the provider is unavailable or misconfigured.
    """

    def __init__(
        self,
        policy: OidcDiscoveryPolicy,
        *,
        timeout_seconds: float = 5.0,
        opener: OpenerDirector | None = None,
    ) -> None:
        if not 0.1 <= timeout_seconds <= 15.0:
            raise ValueError("Discovery timeout must be between 0.1 and 15 seconds")
        self._url = policy.discovery_url
        self._timeout = timeout_seconds
        self._opener = opener or build_opener(
            HTTPSHandler(context=ssl.create_default_context()), _NoRedirect()
        )

    def fetch(self, url: str) -> object:
        if url != self._url:
            raise OidcDiscoveryError("OIDC discovery URL is not allowlisted")
        request = Request(
            self._url,
            method="GET",
            headers={"Accept": "application/json", "User-Agent": "ASCA-OIDC-discovery/1.0"},
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                status = response.status
                raw_content_type = response.headers.get("Content-Type", "")
                if not isinstance(raw_content_type, str):
                    raise OidcDiscoveryError("OIDC discovery HTTP response is invalid")
                content_type = raw_content_type.split(";", 1)[0]
                if status != 200 or content_type.lower().strip() != "application/json":
                    raise OidcDiscoveryError("OIDC discovery HTTP response is invalid")
                data = response.read(_MAX_METADATA_BYTES + 1)
                if len(data) > _MAX_METADATA_BYTES:
                    raise OidcDiscoveryError("OIDC discovery document exceeds size limit")
        except OidcDiscoveryError:
            raise
        except (HTTPError, URLError, TimeoutError, OSError, ValueError):
            raise OidcDiscoveryError("OIDC discovery HTTPS request failed") from None

        try:
            return json.loads(
                data.decode("utf-8"),
                object_pairs_hook=_unique_object_pairs,
                parse_constant=_reject_json_constant,
            )
        except OidcDiscoveryError:
            raise
        except (UnicodeError, ValueError, TypeError, RecursionError):
            raise OidcDiscoveryError("OIDC discovery response is not valid strict JSON") from None
