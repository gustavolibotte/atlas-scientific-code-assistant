"""Non-authenticating denial marker for the isolated native callback lifecycle.

Neither an HTTP callback nor an accepted authorization denial proves an
identity, trusted socket provenance, client registration, or CERN membership.
"""

from dataclasses import dataclass, field
from typing import Literal


class OidcNativeLifecycleError(ValueError):
    """Sanitized refusal of a native callback lifecycle transition."""


@dataclass(frozen=True, slots=True)
class NativeCallbackDenied:
    """A correlated authorization denial, never a login or identity receipt."""

    status: Literal["denied"] = field(default="denied", init=False)
    login: Literal["not_implemented"] = field(default="not_implemented", init=False)
