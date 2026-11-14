"""Validated knowledge settings (frozen dataclasses; Pydantic stays in ``config.py``).

Adapters trust these values. No setting can disable TLS verification or raise a byte cap;
timeouts are 1.0 to 30.0 seconds.
"""

import math
import os
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final
from urllib.parse import urlsplit

from asca.application.knowledge.models import PROVIDER_ID_RE
from asca.application.knowledge.text import is_block
from asca.domain.provenance import AccessClass, SourceAuthority
from asca.infrastructure.knowledge.secrets import SECRET_ENV_RE
from asca.infrastructure.knowledge.url_guard import validate_endpoint_url

TIMEOUT_MIN: Final = 1.0
TIMEOUT_MAX: Final = 30.0
ARXIV_MIN_INTERVAL: Final = 3.0
MCP_SERVERS_MAX: Final = 16
ARGS_MAX: Final = 32
ARG_MAX: Final = 1000
ENV_MAX: Final = 16
SERVER_ID_RE: Final = re.compile(r"[a-z][a-z0-9-]{0,31}")
TOOL_NAME_RE: Final = re.compile(r"[A-Za-z0-9_.-]{1,64}")
ARG_NAME_RE: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
CHILD_ENV_RE: Final = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
CHILD_ENV_REFUSED_PREFIXES: Final = ("LD_", "DYLD_", "PYTHON")
MCP_CEILINGS: Final = frozenset(
    {SourceAuthority.WORKING_MATERIAL, SourceAuthority.AUTOMATED_INFERENCE}
)
_PROVIDER_ID = re.compile(PROVIDER_ID_RE)
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _fail(field_name: str) -> ValueError:
    return ValueError(f"invalid knowledge setting: {field_name}")


def _bool(name: str, value: object) -> None:
    if not isinstance(value, bool):
        raise _fail(name)


def _timeout(name: str, value: object) -> None:
    if (
        not isinstance(value, int | float)
        or isinstance(value, bool)
        or not math.isfinite(value)
        or not TIMEOUT_MIN <= value <= TIMEOUT_MAX
    ):
        raise _fail(name)


def _match(name: str, value: object, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _fail(name)


def _enum(name: str, value: object, kind: type) -> None:
    if not isinstance(value, kind):
        raise _fail(name)


class ProxyMode(StrEnum):
    ENV = "env"
    NONE = "none"
    EXPLICIT = "explicit"


@dataclass(frozen=True, slots=True)
class NetworkSettings:
    proxy_mode: ProxyMode = ProxyMode.ENV
    proxy_url: str | None = None
    """EXPLICIT only: ``http(s)://host:port`` with no userinfo, path or query."""

    def __post_init__(self) -> None:
        _enum("network.proxy_mode", self.proxy_mode, ProxyMode)
        if (self.proxy_mode is ProxyMode.EXPLICIT) != (self.proxy_url is not None):
            raise _fail("network.proxy_url")
        if self.proxy_url is not None and not _is_proxy_url(self.proxy_url):
            raise _fail("network.proxy_url")


def _is_proxy_url(value: object) -> bool:
    if not isinstance(value, str) or len(value) > 500:
        return False
    if any(char.isspace() or not char.isprintable() for char in value):
        return False
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError:
        return False
    return (
        parts.scheme in ("http", "https")
        and bool(parts.hostname)
        and "@" not in parts.netloc
        and port is not None
        and port > 0
        and parts.path in ("", "/")
        and "?" not in value
        and "#" not in value
    )


@dataclass(frozen=True, slots=True)
class InspireSettings:
    enabled: bool = True
    timeout_s: float = 10.0

    def __post_init__(self) -> None:
        _bool("inspire.enabled", self.enabled)
        _timeout("inspire.timeout_s", self.timeout_s)


@dataclass(frozen=True, slots=True)
class ArxivSettings:
    enabled: bool = True
    timeout_s: float = 15.0
    min_interval_s: float = ARXIV_MIN_INTERVAL

    def __post_init__(self) -> None:
        _bool("arxiv.enabled", self.enabled)
        _timeout("arxiv.timeout_s", self.timeout_s)
        if (
            not isinstance(self.min_interval_s, int | float)
            or isinstance(self.min_interval_s, bool)
            or not ARXIV_MIN_INTERVAL <= self.min_interval_s <= 60.0
        ):
            raise _fail("arxiv.min_interval_s")


@dataclass(frozen=True, slots=True)
class HepdataSettings:
    enabled: bool = True
    timeout_s: float = 10.0

    def __post_init__(self) -> None:
        _bool("hepdata.enabled", self.enabled)
        _timeout("hepdata.timeout_s", self.timeout_s)


@dataclass(frozen=True, slots=True)
class LocalLibrarySettings:
    enabled: bool
    root: str
    """Absolute after ``~`` expansion."""
    timeout_s: float = 5.0

    def __post_init__(self) -> None:
        _bool("local.enabled", self.enabled)
        if (
            not isinstance(self.root, str)
            or not self.root
            or "\x00" in self.root
            or not os.path.isabs(os.path.expanduser(self.root))
        ):
            raise _fail("local.root")
        _timeout("local.timeout_s", self.timeout_s)


class McpTransport(StrEnum):
    STREAMABLE_HTTP = "streamable_http"
    STDIO = "stdio"


class McpResultKind(StrEnum):
    DOCUMENTS = "documents"
    GENERATED = "generated"


@dataclass(frozen=True, slots=True)
class McpServerSettings:
    server_id: str
    """Provider id = ``"mcp:" + server_id``."""
    enabled: bool
    transport: McpTransport
    url: str | None
    """STREAMABLE_HTTP only."""
    token_env: str | None
    """STREAMABLE_HTTP only: the NAME of an ``ASCA_`` variable, never the value."""
    allow_private_network: bool
    allow_insecure_loopback: bool
    command: str | None
    """STDIO only: absolute, resolved with realpath by the configuration loader."""
    args: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    """STDIO only: (child variable name, ``ASCA_`` source variable name) pairs."""
    access_class: AccessClass
    access_conditions: str | None
    max_query_access: AccessClass
    authority_ceiling: SourceAuthority
    result_kind: McpResultKind
    search_tool: str
    search_query_arg: str
    search_limit_arg: str | None
    fetch_tool: str | None
    """None: the server does not support fetch."""
    fetch_id_arg: str
    expected_tools_sha256: str | None
    timeout_s: float = 20.0

    def __post_init__(self) -> None:
        _match("mcp.server_id", self.server_id, SERVER_ID_RE)
        _bool("mcp.enabled", self.enabled)
        _enum("mcp.transport", self.transport, McpTransport)
        _bool("mcp.allow_private_network", self.allow_private_network)
        _bool("mcp.allow_insecure_loopback", self.allow_insecure_loopback)
        if self.transport is McpTransport.STREAMABLE_HTTP:
            self._check_http()
        else:
            self._check_stdio()
        _enum("mcp.access_class", self.access_class, AccessClass)
        if (self.access_class is AccessClass.PUBLIC) != (self.access_conditions is None):
            raise _fail("mcp.access_conditions")
        if self.access_conditions is not None and (
            not is_block(self.access_conditions) or len(self.access_conditions) > 2000
        ):
            raise _fail("mcp.access_conditions")
        _enum("mcp.max_query_access", self.max_query_access, AccessClass)
        if self.authority_ceiling not in MCP_CEILINGS:
            raise _fail("mcp.authority_ceiling")
        _enum("mcp.result_kind", self.result_kind, McpResultKind)
        _match("mcp.search_tool", self.search_tool, TOOL_NAME_RE)
        _match("mcp.search_query_arg", self.search_query_arg, ARG_NAME_RE)
        if self.search_limit_arg is not None:
            _match("mcp.search_limit_arg", self.search_limit_arg, ARG_NAME_RE)
        if self.fetch_tool is not None:
            _match("mcp.fetch_tool", self.fetch_tool, TOOL_NAME_RE)
        _match("mcp.fetch_id_arg", self.fetch_id_arg, ARG_NAME_RE)
        if self.expected_tools_sha256 is not None:
            _match("mcp.expected_tools_sha256", self.expected_tools_sha256, _SHA256)
        _timeout("mcp.timeout_s", self.timeout_s)

    def _check_http(self) -> None:
        if self.url is None or self.command is not None or self.args or self.env:
            raise _fail("mcp.transport")
        validate_endpoint_url(self.url, allow_insecure_loopback=self.allow_insecure_loopback)
        if self.token_env is not None:
            _match("mcp.token_env", self.token_env, SECRET_ENV_RE)

    def _check_stdio(self) -> None:
        if self.url is not None or self.token_env is not None:
            raise _fail("mcp.transport")
        command = self.command
        if not isinstance(command, str) or "\x00" in command or not os.path.isabs(command):
            raise _fail("mcp.command")
        if (
            not isinstance(self.args, tuple)
            or len(self.args) > ARGS_MAX
            or not all(
                isinstance(arg, str) and len(arg) <= ARG_MAX and "\x00" not in arg
                for arg in self.args
            )
        ):
            raise _fail("mcp.args")
        if not isinstance(self.env, tuple) or len(self.env) > ENV_MAX:
            raise _fail("mcp.env")
        for pair in self.env:
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise _fail("mcp.env")
            child, source = pair
            _match("mcp.env", child, CHILD_ENV_RE)
            _match("mcp.env", source, SECRET_ENV_RE)
            if child.startswith(CHILD_ENV_REFUSED_PREFIXES):
                raise _fail("mcp.env")

    @property
    def provider_id(self) -> str:
        return f"mcp:{self.server_id}"


def _configured_ids(
    local: "LocalLibrarySettings | None", mcp: tuple[McpServerSettings, ...]
) -> set[str]:
    ids = {"inspire", "arxiv", "hepdata", *(server.provider_id for server in mcp)}
    if local is not None:
        ids.add("local")
    return ids


@dataclass(frozen=True, slots=True)
class KnowledgeSettings:
    precedence: tuple[str, ...] = ()
    network: NetworkSettings = field(default_factory=NetworkSettings)
    inspire: InspireSettings = field(default_factory=InspireSettings)
    arxiv: ArxivSettings = field(default_factory=ArxivSettings)
    hepdata: HepdataSettings = field(default_factory=HepdataSettings)
    local: LocalLibrarySettings | None = None
    mcp: tuple[McpServerSettings, ...] = ()

    def __post_init__(self) -> None:
        _enum("network", self.network, NetworkSettings)
        _enum("inspire", self.inspire, InspireSettings)
        _enum("arxiv", self.arxiv, ArxivSettings)
        _enum("hepdata", self.hepdata, HepdataSettings)
        if self.local is not None:
            _enum("local", self.local, LocalLibrarySettings)
        if (
            not isinstance(self.mcp, tuple)
            or len(self.mcp) > MCP_SERVERS_MAX
            or not all(isinstance(server, McpServerSettings) for server in self.mcp)
        ):
            raise _fail("mcp")
        server_ids = [server.server_id for server in self.mcp]
        if len(set(server_ids)) != len(server_ids):
            raise _fail("mcp")
        if not isinstance(self.precedence, tuple) or len(set(self.precedence)) != len(
            self.precedence
        ):
            raise _fail("precedence")
        configured = _configured_ids(self.local, self.mcp)
        for item in self.precedence:
            _match("precedence", item, _PROVIDER_ID)
            if item not in configured:
                raise _fail("precedence")


DEFAULT_SETTINGS: Final[KnowledgeSettings] = KnowledgeSettings()
"""INSPIRE, arXiv and HEPData enabled; no local library; no MCP server."""
