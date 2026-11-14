"""Knowledge configuration: a permission-checked TOML file mapped to ``KnowledgeSettings``.

The file can launch processes (stdio MCP servers), so it is treated as a code-execution
input:

- it is found through ``--config``, then ``ASCA_KNOWLEDGE_CONFIG``, then
  ``$XDG_CONFIG_HOME/asca/knowledge.toml`` (default ``~/.config/asca/knowledge.toml``),
  and **never** in the working directory;
- it is opened with ``O_NOFOLLOW`` and must be a regular file of at most 64 KiB, owned
  by the current user and not group- or world-writable; with a stdio MCP server its
  directory must not be group- or world-writable either;
- every table forbids unknown keys, so an inline ``token`` or ``password`` is refused;
  secrets are named by ``ASCA_`` environment variables only;
- errors carry a fixed code and ``loc``/``type`` details, never an input value.

Pydantic only checks shapes here; the frozen settings dataclasses enforce the values.
"""

import os
import stat
import tomllib
from collections.abc import Callable, Mapping
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, ValidationError

from asca.domain.provenance import AccessClass, SourceAuthority
from asca.infrastructure.knowledge.settings import (
    ArxivSettings,
    HepdataSettings,
    InspireSettings,
    KnowledgeSettings,
    LocalLibrarySettings,
    McpResultKind,
    McpServerSettings,
    McpTransport,
    NetworkSettings,
    ProxyMode,
)
from asca.infrastructure.knowledge.url_guard import UnsafeUrl

CONFIG_FORMAT: Final = "asca-knowledge/1"
CONFIG_ENV: Final = "ASCA_KNOWLEDGE_CONFIG"
CONFIG_MAX_BYTES: Final = 65_536
DEFAULT_PRECEDENCE: Final = ("inspire", "arxiv", "hepdata", "local")
_WRITABLE_BY_OTHERS: Final = 0o022
_HTTP_ONLY_KEYS: Final = ("url", "token_env", "allow_private_network", "allow_insecure_loopback")
_STDIO_ONLY_KEYS: Final = ("command", "args", "env")
_SETTING_PREFIX: Final = "invalid knowledge setting: "

StatFunction = Callable[[int], os.stat_result]


class KnowledgeConfigError(Exception):
    """A configuration could not be used. The message never contains a value or a path."""

    CODES: Final = frozenset(
        {
            "config_missing",
            "config_unsafe_file",
            "config_unsafe_directory",
            "config_too_large",
            "config_invalid",
        }
    )

    def __init__(self, code: str, details: tuple[str, ...] = ()) -> None:
        if code not in self.CODES:
            raise ValueError("unknown configuration error code")
        self.code = code
        self.details = details
        super().__init__(f"knowledge configuration error: {code}")


# ---------------------------------------------------------------------- schema


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


Timeout = Annotated[float, Field(allow_inf_nan=False)]
AccessName = Literal["public", "internal", "restricted"]


class _Federation(_Strict):
    precedence: list[StrictStr] | None = Field(default=None, max_length=32)


class _Network(_Strict):
    proxy: StrictStr = "env"


class _Inspire(_Strict):
    enabled: StrictBool = True
    timeout_s: Timeout = 10.0


class _Arxiv(_Strict):
    enabled: StrictBool = True
    timeout_s: Timeout = 15.0
    min_interval_s: Timeout = 3.0


class _Hepdata(_Strict):
    enabled: StrictBool = True
    timeout_s: Timeout = 10.0


class _Local(_Strict):
    enabled: StrictBool
    root: StrictStr = Field(max_length=4096)
    timeout_s: Timeout = 5.0


class _Providers(_Strict):
    inspire: _Inspire = Field(default_factory=_Inspire)
    arxiv: _Arxiv = Field(default_factory=_Arxiv)
    hepdata: _Hepdata = Field(default_factory=_Hepdata)
    local: _Local | None = None


class _McpServer(_Strict):
    enabled: StrictBool
    transport: Literal["streamable_http", "stdio"]
    url: StrictStr | None = Field(default=None, max_length=2000)
    token_env: StrictStr | None = Field(default=None, max_length=70)
    allow_private_network: StrictBool = False
    allow_insecure_loopback: StrictBool = False
    command: StrictStr | None = Field(default=None, max_length=4096)
    args: list[StrictStr] = Field(default_factory=list, max_length=32)
    env: dict[StrictStr, StrictStr] = Field(default_factory=dict, max_length=16)
    access_class: AccessName
    access_conditions: StrictStr | None = Field(default=None, max_length=2000)
    max_query_access: AccessName | None = None
    authority_ceiling: Literal["working_material", "automated_inference"] = "working_material"
    result_kind: Literal["documents", "generated"] = "documents"
    search_tool: StrictStr = Field(default="search", max_length=64)
    search_query_arg: StrictStr = Field(default="query", max_length=64)
    search_limit_arg: StrictStr | None = Field(default=None, max_length=64)
    fetch_tool: StrictStr | None = Field(default=None, max_length=64)
    fetch_id_arg: StrictStr = Field(default="id", max_length=64)
    expected_tools_sha256: StrictStr | None = Field(default=None, max_length=64)
    timeout_s: Timeout = 20.0


class _Config(_Strict):
    format: Literal["asca-knowledge/1"]
    federation: _Federation = Field(default_factory=_Federation)
    network: _Network = Field(default_factory=_Network)
    providers: _Providers = Field(default_factory=_Providers)
    mcp: dict[StrictStr, _McpServer] = Field(default_factory=dict, max_length=16)


# ---------------------------------------------------------------------- paths


def _home(environ: Mapping[str, str]) -> str | None:
    home = environ.get("HOME", "")
    return home if home and os.path.isabs(home) else None


def default_config_path(environ: Mapping[str, str]) -> str | None:
    """``$XDG_CONFIG_HOME/asca/knowledge.toml``; never relative, never the working directory.

    A relative ``XDG_CONFIG_HOME`` is ignored (XDG requires an absolute path). Without an
    absolute ``HOME`` there is no default path.
    """
    xdg = environ.get("XDG_CONFIG_HOME", "")
    if xdg and os.path.isabs(xdg):
        return os.path.join(xdg, "asca", "knowledge.toml")
    home = _home(environ)
    if home is None:
        return None
    return os.path.join(home, ".config", "asca", "knowledge.toml")


def resolve_config_path(path: str | None, environ: Mapping[str, str]) -> tuple[str | None, bool]:
    """Return ``(path, explicit)``: ``--config``, then the environment, then the XDG default."""
    if path:
        return path, True
    from_env = environ.get(CONFIG_ENV, "")
    if from_env:
        return from_env, True
    return default_config_path(environ), False


def _expand_user(value: str, environ: Mapping[str, str], field: str) -> str:
    """Expand a leading ``~`` from ``environ['HOME']``; ``~user`` forms are refused."""
    if value == "~" or value.startswith("~/"):
        home = _home(environ)
        if home is None:
            raise KnowledgeConfigError("config_invalid", (f"{field}: home_unavailable",))
        return home + value[1:]
    if value.startswith("~"):
        raise KnowledgeConfigError("config_invalid", (f"{field}: not_absolute",))
    return value


# ---------------------------------------------------------------------- file safety


def _read_config_file(path: str, explicit: bool, fstat: StatFunction) -> bytes | None:
    if os.name != "posix":  # pragma: no cover - POSIX only (ADR 0040)
        raise KnowledgeConfigError("config_unsafe_file")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        if explicit:
            raise KnowledgeConfigError("config_missing") from None
        return None
    except OSError:
        # ELOOP (a symlink), EACCES, ENOTDIR, ...: never followed, never guessed.
        raise KnowledgeConfigError("config_unsafe_file") from None
    try:
        status = fstat(fd)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != os.getuid()
            or status.st_mode & _WRITABLE_BY_OTHERS
        ):
            raise KnowledgeConfigError("config_unsafe_file")
        if status.st_size > CONFIG_MAX_BYTES:
            raise KnowledgeConfigError("config_too_large")
        chunks: list[bytes] = []
        total = 0
        while total <= CONFIG_MAX_BYTES:
            chunk = os.read(fd, CONFIG_MAX_BYTES + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError:
        raise KnowledgeConfigError("config_unsafe_file") from None
    finally:
        os.close(fd)
    if total > CONFIG_MAX_BYTES:
        raise KnowledgeConfigError("config_too_large")
    return b"".join(chunks)


def _check_directory(path: str) -> None:
    try:
        status = os.stat(os.path.dirname(os.path.abspath(path)))
    except OSError:  # pragma: no cover - the directory vanished after the file was read
        raise KnowledgeConfigError("config_unsafe_directory") from None
    if status.st_mode & _WRITABLE_BY_OTHERS:
        raise KnowledgeConfigError("config_unsafe_directory")


def check_command(command: str, environ: Mapping[str, str], field: str) -> str:
    """Resolve a stdio command and apply the file checks of spec 9.1; return the realpath.

    The command must be absolute after ``~`` expansion and resolve to an existing,
    executable regular file that is neither group- nor world-writable and is owned by
    the current user or root.
    """
    expanded = _expand_user(command, environ, field)
    if "\x00" in expanded or not os.path.isabs(expanded):
        raise KnowledgeConfigError("config_invalid", (f"{field}: not_absolute",))
    resolved = os.path.realpath(expanded)
    try:
        status = os.stat(resolved)
    except OSError:
        raise KnowledgeConfigError("config_invalid", (f"{field}: unsafe_command",)) from None
    if (
        not stat.S_ISREG(status.st_mode)
        or not os.access(resolved, os.X_OK)
        or status.st_mode & _WRITABLE_BY_OTHERS
        or status.st_uid not in (os.getuid(), 0)
    ):
        raise KnowledgeConfigError("config_invalid", (f"{field}: unsafe_command",))
    return resolved


# ---------------------------------------------------------------------- mapping


def _validation_details(error: ValidationError) -> tuple[str, ...]:
    """Only ``loc`` and ``type`` of each error; never the input value."""
    details: list[str] = []
    for item in error.errors(include_input=False, include_url=False, include_context=False):
        loc = ".".join(str(part) for part in item["loc"])
        details.append(f"{loc}: {item['type']}")
    return tuple(details)


def _network(proxy: str) -> NetworkSettings:
    if proxy == "env":
        return NetworkSettings(ProxyMode.ENV)
    if proxy == "none":
        return NetworkSettings(ProxyMode.NONE)
    return NetworkSettings(ProxyMode.EXPLICIT, proxy)


def _mcp_server(server_id: str, raw: _McpServer, environ: Mapping[str, str]) -> McpServerSettings:
    field = f"mcp.{server_id}"
    transport = McpTransport(raw.transport)
    forbidden = _STDIO_ONLY_KEYS if transport is McpTransport.STREAMABLE_HTTP else _HTTP_ONLY_KEYS
    present = sorted(raw.model_fields_set.intersection(forbidden))
    if present:
        raise KnowledgeConfigError(
            "config_invalid", tuple(f"{field}.{key}: other_transport" for key in present)
        )
    command = raw.command
    if transport is McpTransport.STDIO:
        if command is None:
            raise KnowledgeConfigError("config_invalid", (f"{field}.command: missing",))
        command = check_command(command, environ, f"{field}.command")
    access = AccessClass(raw.access_class)
    max_query = AccessClass(raw.max_query_access) if raw.max_query_access else access
    return McpServerSettings(
        server_id=server_id,
        enabled=raw.enabled,
        transport=transport,
        url=raw.url,
        token_env=raw.token_env,
        allow_private_network=raw.allow_private_network,
        allow_insecure_loopback=raw.allow_insecure_loopback,
        command=command,
        args=tuple(raw.args),
        env=tuple(raw.env.items()),
        access_class=access,
        access_conditions=raw.access_conditions,
        max_query_access=max_query,
        authority_ceiling=SourceAuthority(raw.authority_ceiling),
        result_kind=McpResultKind(raw.result_kind),
        search_tool=raw.search_tool,
        search_query_arg=raw.search_query_arg,
        search_limit_arg=raw.search_limit_arg,
        fetch_tool=raw.fetch_tool,
        fetch_id_arg=raw.fetch_id_arg,
        expected_tools_sha256=raw.expected_tools_sha256,
        timeout_s=raw.timeout_s,
    )


def _settings(config: _Config, environ: Mapping[str, str]) -> KnowledgeSettings:
    providers = config.providers
    local = None
    if providers.local is not None:
        root = _expand_user(providers.local.root, environ, "providers.local.root")
        local = LocalLibrarySettings(providers.local.enabled, root, providers.local.timeout_s)
    return KnowledgeSettings(
        precedence=tuple(config.federation.precedence or ()),
        network=_network(config.network.proxy),
        inspire=InspireSettings(providers.inspire.enabled, providers.inspire.timeout_s),
        arxiv=ArxivSettings(
            providers.arxiv.enabled, providers.arxiv.timeout_s, providers.arxiv.min_interval_s
        ),
        hepdata=HepdataSettings(providers.hepdata.enabled, providers.hepdata.timeout_s),
        local=local,
        mcp=tuple(_mcp_server(server_id, raw, environ) for server_id, raw in config.mcp.items()),
    )


def parse_settings(data: bytes, environ: Mapping[str, str]) -> KnowledgeSettings:
    """Map the bytes of a configuration file to validated settings."""
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise KnowledgeConfigError("config_invalid", ("toml: syntax",)) from None
    try:
        config = _Config.model_validate(document)
    except ValidationError as error:
        raise KnowledgeConfigError("config_invalid", _validation_details(error)) from None
    try:
        return _settings(config, environ)
    except UnsafeUrl as error:
        raise KnowledgeConfigError("config_invalid", (f"url: {error.code}",)) from None
    except ValueError as error:
        message = str(error)
        detail = message[len(_SETTING_PREFIX) :] if message.startswith(_SETTING_PREFIX) else "value"
        raise KnowledgeConfigError("config_invalid", (f"{detail}: invalid",)) from None


def load_settings(
    path: str | None,
    environ: Mapping[str, str],
    *,
    _stat: StatFunction = os.fstat,
) -> KnowledgeSettings:
    """Load the effective settings; ``DEFAULT_SETTINGS`` when no default file exists.

    ``path`` is the ``--config`` argument. Raise ``KnowledgeConfigError``.
    """
    resolved, explicit = resolve_config_path(path, environ)
    if resolved is None:
        return KnowledgeSettings()
    data = _read_config_file(resolved, explicit, _stat)
    if data is None:
        return KnowledgeSettings()
    settings = parse_settings(data, environ)
    if any(server.transport is McpTransport.STDIO for server in settings.mcp):
        _check_directory(resolved)
    return settings


def effective_precedence(settings: KnowledgeSettings) -> tuple[str, ...]:
    """Configured precedence first, then inspire, arxiv, hepdata, local, then MCP servers.

    Only configured providers are listed; this is the order the federation reports in.
    """
    configured = [
        item for item in DEFAULT_PRECEDENCE if item != "local" or settings.local is not None
    ]
    configured += [server.provider_id for server in settings.mcp]
    listed = [item for item in settings.precedence if item in configured]
    return (*listed, *(item for item in configured if item not in listed))
