"""Strict JWS signature-checking result; claims and key provenance are NOT trusted.

The absence of verified OIDC claims means this object is never a principal,
user session, authorization decision, or evidence of CERN identity.
"""

from dataclasses import dataclass, field


class OidcJwsError(ValueError):
    """Sanitized JWS validation error; never includes tokens or public keys."""


@dataclass(frozen=True, slots=True)
class SignatureCheckedUntrustedOidcPayload:
    """Payload bytes from a correctly signed JWS under the supplied untrusted key.

    Source provenance and claims still require independent security checks. These
    objects can be forged by Python callers and must not confer authority.
    """

    algorithm: str
    kid: str
    payload: bytes = field(repr=False)
