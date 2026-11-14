"""Builders shared by the MCP adapter tests (settings, providers, stdio arguments).

Everything is synthetic. The canary token is a fake RFC 6750 value used only in tests.
"""

from __future__ import annotations

import functools
import os
import shlex
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

from fake_mcp_server import FakeState, build_server
from knowledge_contract import RETRIEVED_AT

from asca.application.knowledge.models import KnowledgeQuery
from asca.domain.provenance import AccessClass, SourceAuthority
from asca.infrastructure.knowledge.mcp_client import McpKnowledgeProvider, build_mcp_client
from asca.infrastructure.knowledge.settings import (
    McpResultKind,
    McpServerSettings,
    McpTransport,
    NetworkSettings,
    ProxyMode,
)

TOKEN = "asca-test-canary-token-6f1e2d3c4b5a"
TOKEN_ENV = "ASCA_TEST_MCP_TOKEN"
CONDITIONS = "Synthetic internal test material."
FAKE_SERVER = Path(__file__).with_name("fake_mcp_server.py")
NO_PROXY = NetworkSettings(proxy_mode=ProxyMode.NONE)
INTERNAL_QUERY = KnowledgeQuery("calorimeter energy", 5, AccessClass.INTERNAL)


class FixedClock:
    def now(self) -> datetime:
        return RETRIEVED_AT


@functools.cache
def trusted_python() -> str:
    """A private, user-owned wrapper that executes the test interpreter.

    The stdio adapter refuses a command that is group- or world-writable or owned by
    another user. Some interpreters fail that check on CI hosts (for example the
    python.org framework build on macOS runners is group-writable by ``admin``), so the
    tests run the real interpreter through a wrapper the current user owns with mode 0755.
    """
    directory = Path(tempfile.mkdtemp(prefix="asca-mcp-python-"))
    directory.chmod(0o700)
    wrapper = directory / "python"
    interpreter = os.path.realpath(sys.executable)
    # ``env -u`` drops the variables the shell itself exports, so the child sees exactly
    # the environment the adapter built (BSD and GNU ``env`` both support ``-u``).
    wrapper.write_text(
        "#!/bin/sh\n"
        f'exec /usr/bin/env -u PWD -u OLDPWD -u SHLVL -u _ {shlex.quote(interpreter)} "$@"\n',
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    return str(wrapper)


def make_settings(**overrides: Any) -> McpServerSettings:
    """A stdio server running the fake server with the real (resolved) interpreter."""
    values: dict[str, Any] = {
        "server_id": "test",
        "enabled": True,
        "transport": McpTransport.STDIO,
        "url": None,
        "token_env": None,
        "allow_private_network": False,
        "allow_insecure_loopback": False,
        "command": trusted_python(),
        "args": stdio_args("normal"),
        "env": (),
        "access_class": AccessClass.INTERNAL,
        "access_conditions": CONDITIONS,
        "max_query_access": AccessClass.INTERNAL,
        "authority_ceiling": SourceAuthority.WORKING_MATERIAL,
        "result_kind": McpResultKind.DOCUMENTS,
        "search_tool": "search",
        "search_query_arg": "query",
        "search_limit_arg": "limit",
        "fetch_tool": "fetch",
        "fetch_id_arg": "id",
        "expected_tools_sha256": None,
        "timeout_s": 10.0,
    }
    values.update(overrides)
    return McpServerSettings(**values)


def http_settings(url: str, **overrides: Any) -> McpServerSettings:
    values: dict[str, Any] = {
        "transport": McpTransport.STREAMABLE_HTTP,
        "url": url,
        "token_env": TOKEN_ENV,
        "allow_insecure_loopback": True,
        "command": None,
        "args": (),
    }
    values.update(overrides)
    return make_settings(**values)


def stdio_args(mode: str, *, pid_file: Path | None = None) -> tuple[str, ...]:
    """Arguments for the fake server: the test virtualenv's site-packages, then the mode."""
    args: list[str] = [str(FAKE_SERVER)]
    for entry in sys.path:
        if entry.endswith("site-packages"):
            args += ["--site", entry]
    if pid_file is not None:
        args += ["--pid-file", str(pid_file)]
    args.append(mode)
    return tuple(args)


def in_process_provider(
    mode: str = "normal",
    *,
    state: FakeState | None = None,
    settings: McpServerSettings | None = None,
    environ: Mapping[str, str] | None = None,
    token: str | None = None,
    **server_options: Any,
) -> McpKnowledgeProvider:
    """A provider wired to an in-process fake server through the ``connector`` seam.

    ``server_options`` go to ``build_server`` (``tools``, ``page_size``, ``respond``).
    """
    server = build_server(mode, state=state, token=token, **server_options)
    chosen = settings or make_settings()
    return McpKnowledgeProvider(
        chosen,
        network=NO_PROXY,
        clock=FixedClock(),
        connector=lambda: build_mcp_client(server, timeout_s=chosen.timeout_s),
        environ={} if environ is None else environ,
    )


def http_provider(
    url: str, *, environ: Mapping[str, str] | None = None, **overrides: Any
) -> McpKnowledgeProvider:
    return McpKnowledgeProvider(
        http_settings(url, **overrides),
        network=NO_PROXY,
        clock=FixedClock(),
        environ={TOKEN_ENV: TOKEN} if environ is None else environ,
    )


def stdio_provider(
    mode: str,
    *,
    pid_file: Path | None = None,
    environ: Mapping[str, str] | None = None,
    **overrides: Any,
) -> McpKnowledgeProvider:
    settings = make_settings(args=stdio_args(mode, pid_file=pid_file), **overrides)
    return McpKnowledgeProvider(
        settings, network=NO_PROXY, clock=FixedClock(), environ={} if environ is None else environ
    )


def with_settings(provider_settings: McpServerSettings, **overrides: Any) -> McpServerSettings:
    return replace(provider_settings, **overrides)
