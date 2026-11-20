"""Secret handling: environment-only tokens with an ``ASCA_`` prefix, redacted everywhere.

There is no prompt, no keychain access and no token on the command line. The CLI sets the
``httpx2``, ``httpcore2``, ``mcp`` and ``asyncio`` loggers to WARNING; no module logs
request headers.
"""

import hmac
import re
from collections.abc import Mapping
from typing import Final, NoReturn
from urllib.parse import quote

SECRET_ENV_RE: Final = re.compile(r"ASCA_[A-Z0-9_]{1,60}")
_TOKEN_RE: Final = re.compile(r"[A-Za-z0-9\-._~+/]+=*")
TOKEN_MIN: Final = 16
TOKEN_MAX: Final = 4096
REDACTED: Final = "[REDACTED]"


class RedactedSecret:
    """A secret value that never prints, formats, pickles or hashes."""

    __slots__ = ("_value",)
    _value: str

    def __init__(self, value: str) -> None:
        object.__setattr__(self, "_value", value)

    def reveal(self) -> str:
        return self._value

    def __setattr__(self, name: str, value: object) -> NoReturn:
        raise AttributeError("RedactedSecret is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("RedactedSecret is immutable")

    def __repr__(self) -> str:
        return "<redacted>"

    def __str__(self) -> str:
        return "<redacted>"

    def __format__(self, format_spec: str) -> NoReturn:
        raise TypeError("RedactedSecret cannot be formatted")

    def __reduce__(self) -> NoReturn:
        raise TypeError("RedactedSecret cannot be pickled or copied")

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        raise TypeError("RedactedSecret cannot be pickled or copied")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RedactedSecret):
            return NotImplemented
        return hmac.compare_digest(self._value.encode("utf-8"), other._value.encode("utf-8"))

    def __hash__(self) -> NoReturn:
        raise TypeError("RedactedSecret is not hashable")


def read_secret_env(name: str, environ: Mapping[str, str]) -> RedactedSecret | None:
    """Read a bearer token from ``environ[name]``; never prompts.

    ``name`` must match ``ASCA_[A-Z0-9_]{1,60}``. Unset or empty gives ``None``. The value
    must be an RFC 6750 token of 16 to 4096 characters (this prevents header injection).
    """
    if not isinstance(name, str) or SECRET_ENV_RE.fullmatch(name) is None:
        raise ValueError("secret variable names must match ASCA_[A-Z0-9_]{1,60}")
    value = environ.get(name)
    if not value:
        return None
    if not TOKEN_MIN <= len(value) <= TOKEN_MAX or _TOKEN_RE.fullmatch(value) is None:
        raise ValueError("token_invalid")
    return RedactedSecret(value)


def redact_echoes(text: str, secret: RedactedSecret | None) -> tuple[str, int]:
    """Replace the raw secret and its URL-encoded form with ``[REDACTED]``; return the count."""
    if secret is None:
        return text, 0
    count = 0
    for form in dict.fromkeys((secret.reveal(), quote(secret.reveal(), safe=""))):
        occurrences = text.count(form)
        if occurrences:
            count += occurrences
            text = text.replace(form, REDACTED)
    return text, count
