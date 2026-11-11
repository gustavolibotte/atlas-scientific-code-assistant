"""Explicitly non-authenticating status of the isolated CERN native bootstrap.

This status is descriptive, forgeable Python data, not an identity credential or
proof of registered client configuration. The deployment remains disabled.
"""

from dataclasses import dataclass, field
from typing import Literal


class OidcNativeBootstrapError(ValueError):
    """Sanitized rejection of native pre-authentication composition."""


@dataclass(frozen=True, slots=True)
class NativeOidcIsolationStatus:
    """Fixed scope declaration; never evidence of CERN or ATLAS membership.

    This class intentionally cannot describe a production-ready login. Future
    identity enablement requires a separate, independently reviewed contract.
    """

    mode: Literal["native_loopback"] = field(default="native_loopback", init=False)
    login: Literal["not_implemented"] = field(default="not_implemented", init=False)
    client_registration_attested: Literal[False] = field(default=False, init=False)
    loopback_listener_secured: Literal[False] = field(default=False, init=False)
    production_identity_authority: Literal[False] = field(default=False, init=False)
