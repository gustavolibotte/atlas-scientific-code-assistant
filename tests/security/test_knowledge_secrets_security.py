"""Secret handling: RedactedSecret, environment-only tokens and echo redaction.

The MCP canary runs (success, 401, timeout, echo, cross-origin) drive the MCP client
against a loopback server on 127.0.0.1 with a synthetic canary token.
"""

import asyncio
import copy
import logging
import pickle

import pytest
from mcp_http_server import LoopbackMcpServer
from mcp_testing import INTERNAL_QUERY, TOKEN, TOKEN_ENV, http_provider

from asca.application.knowledge.models import (
    CandidateRef,
    FetchResult,
    ProviderError,
    ProviderErrorKind,
    SearchResult,
)
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


# ---------------------------------------------------------------------- MCP canary runs


def _assert_canary_absent(
    values: list[object], caplog: pytest.LogCaptureFixture, capfd: pytest.CaptureFixture[str]
) -> None:
    for value in values:
        assert TOKEN not in repr(value)
        assert TOKEN not in str(value)
    assert TOKEN not in caplog.text
    for record in caplog.records:
        assert TOKEN not in record.getMessage()
        assert TOKEN not in repr(record.args)
    captured = capfd.readouterr()
    assert TOKEN not in captured.out
    assert TOKEN not in captured.err


@pytest.mark.parametrize("scenario", ["success", "unauthorized", "timeout"])
def test_mcp_canary_token_never_leaks(
    scenario: str, caplog: pytest.LogCaptureFixture, capfd: pytest.CaptureFixture[str]
) -> None:
    caplog.set_level(logging.DEBUG)
    mode = "hang" if scenario == "timeout" else "normal"
    server_token = "another-token-0123456789" if scenario == "unauthorized" else TOKEN
    with LoopbackMcpServer(mode, token=server_token) as server:
        provider = http_provider(server.url, timeout_s=1.0 if scenario == "timeout" else 10.0)
        searched = asyncio.run(provider.search(INTERNAL_QUERY))
        health = asyncio.run(provider.health()) if scenario != "timeout" else None
        fetched = (
            asyncio.run(provider.fetch(CandidateRef("mcp:test", "doc-1")))
            if scenario == "success"
            else None
        )
    if scenario == "success":
        assert isinstance(searched, SearchResult)
        assert isinstance(fetched, FetchResult)
        assert server.requests and all(request.authorized for request in server.requests)
    elif scenario == "unauthorized":
        assert searched == ProviderError(ProviderErrorKind.AUTH_REQUIRED, "http_401", 401)
    else:
        assert searched == ProviderError(ProviderErrorKind.TIMEOUT, "provider_timeout")
    _assert_canary_absent([searched, health, fetched, provider, provider.descriptor], caplog, capfd)


def test_mcp_echoed_token_is_redacted() -> None:
    with LoopbackMcpServer("echo_token", token=TOKEN) as server:
        provider = http_provider(server.url)
        searched = asyncio.run(provider.search(INTERNAL_QUERY))
        fetched = asyncio.run(provider.fetch(CandidateRef("mcp:test", "doc-1")))
    assert isinstance(searched, SearchResult)
    candidate = searched.candidates[0]
    assert candidate.title == f"Echo {REDACTED}"
    assert candidate.snippet == f"The token is {REDACTED}."
    assert candidate.landing_url == f"https://docs.example.org/{REDACTED}"
    assert isinstance(fetched, FetchResult)
    assert fetched.document.text == f"Token {REDACTED} and {REDACTED}."
    assert fetched.document.redactions >= 2
    assert TOKEN not in repr(searched) + repr(fetched)


def test_mcp_bearer_is_never_sent_to_another_origin() -> None:
    with (
        LoopbackMcpServer(token=TOKEN, plain=True) as other,
        LoopbackMcpServer(token=TOKEN, redirect_to=other.url) as server,
    ):
        provider = http_provider(server.url)
        outcome = asyncio.run(provider.search(INTERNAL_QUERY))
    assert isinstance(outcome, ProviderError)
    assert server.requests and server.requests[0].authorized
    assert other.requests == []
    assert TOKEN not in repr(outcome)


def test_mcp_token_variable_must_carry_the_asca_prefix() -> None:
    with pytest.raises(ValueError):
        http_provider("http://127.0.0.1:9/mcp", token_env="GITHUB_TOKEN")
    assert TOKEN_ENV.startswith("ASCA_")
