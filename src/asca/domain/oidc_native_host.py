"""Non-authoritative start data for an isolated native OIDC host transaction.

No bearer token, callback binding, verified identity, or authenticated session
can be obtained from this descriptive result. It is ordinary forgeable data.
"""

from dataclasses import dataclass, field
from typing import Literal


class OidcNativeHostError(ValueError):
    """Sanitized terminal failure of the isolated native transaction host."""


@dataclass(frozen=True, slots=True)
class NativeOidcHostStart:
    """Authorization URL for manual browser handoff, not evidence of login."""

    authorization_url: str = field(repr=False)
    redirect_uri: str
    login: Literal["not_implemented"] = field(default="not_implemented", init=False)
