"""Sanitized errors for untrusted OIDC public-key construction.

Public-key construction validates mathematical parameters; it does not establish
CERN JWKS provenance, a valid JWS signature, an identity, or a login session.
"""


class OidcCryptoKeyError(ValueError):
    """Public JWK parameters cannot be constructed as an approved crypto key."""
