"""Untrusted, socket-derived native OIDC loopback callback declarations.

These are plain, forgeable Python objects. Neither validated HTTP syntax nor a
loopback peer address proves browser origin, a consumed state or CERN identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class OidcNativeCallbackError(ValueError):
    """Sanitized refusal of an untrusted native OIDC callback request."""


@dataclass(frozen=True, slots=True)
class NativeLoopbackHttpRequest:
    """HTTP request envelope to be populated ONLY by a future local socket listener.

    The sender cannot supply peer/local socket properties through query strings,
    HTTP headers or forwarded headers. A caller-constructed object is NOT proof
    that a real loopback connection occurred.
    """

    method: str
    request_target: str = field(repr=False)
    http_version: str
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    peer_ip: str
    local_ip: str
    local_port: int
    body: bytes = field(default=b"", repr=False)


@dataclass(frozen=True, slots=True)
class ParsedUntrustedNativeCallback:
    """Strictly parsed query, but NOT an authorization grant or login.

    The native host must separately obtain its original browser binding from
    protected local state and pass this state/code to the existing single-use
    OIDC exchange. Error callbacks require separate rejection/consumption logic.
    """

    state: str = field(repr=False)
    code: str | None = field(repr=False)
    error: str | None = field(repr=False)
    response_issuer: str | None = field(repr=False)
