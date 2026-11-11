"""Descriptive, non-authenticating native loopback listener binding.

A local socket is not proof of browser origin, CERN identity, or client registration.
The binding is ordinary, forgeable Python data; it grants no authority.
"""

from dataclasses import dataclass, field
from typing import Literal


class OidcNativeListenerError(ValueError):
    """Sanitized refusal or terminal failure of a native loopback listener."""


@dataclass(frozen=True, slots=True)
class NativeLoopbackListenerBinding:
    """Observed local socket endpoint, never an authenticated identity."""

    host: Literal["127.0.0.1", "::1"]
    port: int
    redirect_uri: str
    login: Literal["not_implemented"] = field(default="not_implemented", init=False)
