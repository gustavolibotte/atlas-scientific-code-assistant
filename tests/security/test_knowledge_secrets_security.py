"""Secret handling: RedactedSecret, environment-only tokens and echo redaction.

The MCP canary runs (success, 401, timeout, echo, cross-origin) are added with the MCP
client in workstream B.
"""

import copy
import logging
import pickle

import pytest

from asca.infrastructure.knowledge.secrets import (
    REDACTED,
    RedactedSecret,
    read_secret_env,
    redact_echoes,
)

pytestmark = pytest.mark.security

CANARY = "canary-token-0123456789abcdef"


def test_redacted_secret_never_prints() -> None:
    secret = RedactedSecret(CANARY)
    assert repr(secret) == "<redacted>"
    assert str(secret) == "<redacted>"
    assert CANARY not in repr([secret, {"token": secret}])
    assert secret.reveal() == CANARY


def test_redacted_secret_refuses_formatting_pickling_copying_and_hashing() -> None:
    secret = RedactedSecret(CANARY)
    with pytest.raises(TypeError):
        f"{secret}"
    with pytest.raises(TypeError):
        format(secret, "s")
    with pytest.raises(TypeError):
        pickle.dumps(secret)
    with pytest.raises(TypeError):
        copy.copy(secret)
    with pytest.raises(TypeError):
        hash(secret)
    with pytest.raises(TypeError):
        secret.__reduce__()


def test_redacted_secret_is_immutable_and_compares_in_constant_time() -> None:
    secret = RedactedSecret(CANARY)
    with pytest.raises(AttributeError):
        secret._value = "other"
    with pytest.raises(AttributeError):
        del secret._value
    assert secret == RedactedSecret(CANARY)
    assert secret != RedactedSecret(CANARY + "x")
    assert secret != CANARY


def test_redacted_secret_is_absent_from_logs(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    logging.getLogger("asca.test").debug(
        "token %s %r", RedactedSecret(CANARY), RedactedSecret(CANARY)
    )
    assert CANARY not in caplog.text


@pytest.mark.parametrize(
    "name", ["GITHUB_TOKEN", "HOME", "asca_token", "ASCA_", "ASCA_" + "X" * 61]
)
def test_secret_variable_names_need_the_asca_prefix(name: str) -> None:
    with pytest.raises(ValueError) as caught:
        read_secret_env(name, {name: CANARY})
    assert CANARY not in str(caught.value)


def test_unset_or_empty_variables_give_none() -> None:
    assert read_secret_env("ASCA_CHATLAS_TOKEN", {}) is None
    assert read_secret_env("ASCA_CHATLAS_TOKEN", {"ASCA_CHATLAS_TOKEN": ""}) is None


@pytest.mark.parametrize(
    "value",
    [
        "short-token",
        f"{CANARY}\r\nX-Injected: 1",
        f"{CANARY}\n",
        f"{CANARY} space",
        "x" * 4097,
        "é" * 20,
    ],
)
def test_invalid_tokens_are_refused_without_echo(value: str) -> None:
    with pytest.raises(ValueError, match="token_invalid") as caught:
        read_secret_env("ASCA_CHATLAS_TOKEN", {"ASCA_CHATLAS_TOKEN": value})
    assert value not in str(caught.value)


def test_valid_token_is_wrapped() -> None:
    token = "abcDEF0123456789-._~+/=="
    secret = read_secret_env("ASCA_CHATLAS_TOKEN", {"ASCA_CHATLAS_TOKEN": token})
    assert isinstance(secret, RedactedSecret)
    assert secret.reveal() == token


def test_redact_echoes_replaces_raw_and_url_encoded_forms() -> None:
    token = "abc/def+ghi=0123456789"
    secret = RedactedSecret(token)
    text = f"title {token} url https://x.example/?t=abc%2Fdef%2Bghi%3D0123456789 again {token}"
    redacted, count = redact_echoes(text, secret)
    assert count == 3
    assert token not in redacted and "abc%2Fdef" not in redacted
    assert redacted.count(REDACTED) == 3
    assert redact_echoes("nothing here", secret) == ("nothing here", 0)
    assert redact_echoes(f"raw {CANARY}", None) == (f"raw {CANARY}", 0)
    plain = RedactedSecret(CANARY)
    assert redact_echoes(f"{CANARY}{CANARY}", plain) == (REDACTED * 2, 2)
