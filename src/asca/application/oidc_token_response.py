"""Parse bounded, unverified CERN OIDC code-flow token response bytes offline.

Parsing is not ID-token verification, an OAuth authorization decision, or login.
No network, JWKS retrieval, credential persistence, or API routes are involved.
"""

from __future__ import annotations

import json
import re
from decimal import Decimal
from typing import Any

from asca.domain.oidc_token_http import UnverifiedOidcTokenHttpResponse
from asca.domain.oidc_token_response import (
    OidcTokenResponseError,
    ParsedUnverifiedOidcTokenResponse,
)

_MAX_BODY_BYTES = 65_536
_MAX_TOKEN_LENGTH = 32_768
_MAX_SCOPE_LENGTH = 1_024
_MAX_EXPIRY_SECONDS = 604_800
_BEARER_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+={0,64}\Z", re.ASCII)
_COMPACT_JWS = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\Z", re.ASCII)
_SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5B\x5D-\x7E]+\Z", re.ASCII)
_UNEXPECTED_FLOW_FIELDS = frozenset({"error", "error_description", "error_uri", "code", "state"})


def _unique_json_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate members at every nesting depth, including extensions."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OidcTokenResponseError("Duplicate OIDC token response JSON members")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise OidcTokenResponseError("Invalid OIDC token response JSON constant")


def _parse_json_response(response: UnverifiedOidcTokenHttpResponse) -> dict[str, object]:
    if not isinstance(response, UnverifiedOidcTokenHttpResponse):
        raise OidcTokenResponseError("Invalid OIDC token HTTP response object")
    raw = response.body
    if (
        not isinstance(raw, bytes)
        or not 0 < len(raw) <= _MAX_BODY_BYTES
        or response.status_code != 200
    ):
        raise OidcTokenResponseError("Invalid OIDC token HTTP response object")
    try:
        parsed: Any = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_members,
            parse_constant=_reject_json_constant,
            parse_float=Decimal,
        )
    except OidcTokenResponseError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        raise OidcTokenResponseError("Invalid OIDC token response JSON") from None
    if not isinstance(parsed, dict):
        raise OidcTokenResponseError("OIDC token response must be a JSON object")
    return parsed


def _opaque_bearer_token(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= _MAX_TOKEN_LENGTH
        or not _BEARER_TOKEN.fullmatch(value)
    ):
        raise OidcTokenResponseError("Invalid OIDC bearer token value")
    return value


def _id_token(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= _MAX_TOKEN_LENGTH
        or not _COMPACT_JWS.fullmatch(value)
    ):
        raise OidcTokenResponseError("Invalid OIDC ID-token compact representation")
    return value


def _optional_scope(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_SCOPE_LENGTH:
        raise OidcTokenResponseError("Invalid OIDC token response scope")
    parts = value.split(" ")
    if any(not _SCOPE_TOKEN.fullmatch(part) for part in parts) or len(set(parts)) != len(parts):
        raise OidcTokenResponseError("Invalid OIDC token response scope")
    return tuple(parts)


def parse_unverified_oidc_token_response(
    response: UnverifiedOidcTokenHttpResponse,
) -> ParsedUnverifiedOidcTokenResponse:
    """Check token-response structure without trusting token contents.

    RFC 6749/OIDC require access_token, token_type and id_token for this flow.
    expires_in is recommended rather than required. Unknown extension fields
    are ignored (never promoted to authority), as the standards require.
    """
    document = _parse_json_response(response)
    if _UNEXPECTED_FLOW_FIELDS.intersection(document):
        raise OidcTokenResponseError("Unexpected OAuth fields in successful token response")

    access_token = _opaque_bearer_token(document.get("access_token"))
    id_token = _id_token(document.get("id_token"))
    token_type = document.get("token_type")
    if not isinstance(token_type, str) or token_type.casefold() != "bearer":
        raise OidcTokenResponseError("Unsupported OIDC token type")

    expiry: int | None = None
    if "expires_in" in document:
        declared_expiry = document["expires_in"]
        if (
            isinstance(declared_expiry, bool)
            or not isinstance(declared_expiry, int)
            or not 1 <= declared_expiry <= _MAX_EXPIRY_SECONDS
        ):
            raise OidcTokenResponseError("Invalid OIDC token expiration interval")
        expiry = declared_expiry

    refresh: str | None = None
    if "refresh_token" in document:
        refresh = _opaque_bearer_token(document["refresh_token"])

    scope = _optional_scope(document.get("scope"))
    if "scope" in document and document["scope"] is None:
        raise OidcTokenResponseError("Invalid OIDC token response scope")

    return ParsedUnverifiedOidcTokenResponse(
        access_token=access_token,
        id_token=id_token,
        token_type="Bearer",
        expires_in=expiry,
        refresh_token=refresh,
        scope=scope,
    )
