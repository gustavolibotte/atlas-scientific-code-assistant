"""Validated knowledge settings (the frozen dataclasses adapters trust)."""

from dataclasses import replace

import pytest

from asca.domain.provenance import AccessClass, SourceAuthority
from asca.infrastructure.knowledge.settings import (
    DEFAULT_SETTINGS,
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

pytestmark = pytest.mark.unit


def http_server(**changes: object) -> McpServerSettings:
    base = McpServerSettings(
        server_id="chatlas",
        enabled=False,
        transport=McpTransport.STREAMABLE_HTTP,
        url="https://chatlas.example/mcp",
        token_env="ASCA_CHATLAS_TOKEN",
        allow_private_network=False,
        allow_insecure_loopback=False,
        command=None,
        args=(),
        env=(),
        access_class=AccessClass.INTERNAL,
        access_conditions="ATLAS members via CERN SSO",
        max_query_access=AccessClass.INTERNAL,
        authority_ceiling=SourceAuthority.WORKING_MATERIAL,
        result_kind=McpResultKind.DOCUMENTS,
        search_tool="search",
        search_query_arg="query",
        search_limit_arg=None,
        fetch_tool="fetch",
        fetch_id_arg="id",
        expected_tools_sha256=None,
    )
    return replace(base, **changes)  # type: ignore[arg-type]


def stdio_server(**changes: object) -> McpServerSettings:
    return http_server(
        **{
            "server_id": "gitlab",
            "transport": McpTransport.STDIO,
            "url": None,
            "token_env": None,
            "command": "/opt/cerngitlab-mcp/bin/cerngitlab-mcp",
            "args": ("--read-only",),
            "env": (("GITLAB_TOKEN", "ASCA_CERNGITLAB_TOKEN"),),
            **changes,
        }
    )


def test_defaults_enable_public_providers_only() -> None:
    assert DEFAULT_SETTINGS.inspire.enabled and DEFAULT_SETTINGS.arxiv.enabled
    assert DEFAULT_SETTINGS.hepdata.enabled
    assert DEFAULT_SETTINGS.local is None and DEFAULT_SETTINGS.mcp == ()
    assert DEFAULT_SETTINGS.network.proxy_mode is ProxyMode.ENV
    assert DEFAULT_SETTINGS.arxiv.min_interval_s == 3.0


def test_network_settings() -> None:
    assert NetworkSettings(ProxyMode.EXPLICIT, "http://proxy.example:3128").proxy_url
    assert NetworkSettings(ProxyMode.EXPLICIT, "https://proxy.example:8443/").proxy_url
    for mode, url in (
        (ProxyMode.EXPLICIT, None),
        (ProxyMode.ENV, "http://proxy.example:3128"),
        (ProxyMode.EXPLICIT, "http://user:pw@proxy.example:3128"),
        (ProxyMode.EXPLICIT, "http://proxy.example"),
        (ProxyMode.EXPLICIT, "http://proxy.example:3128/path"),
        (ProxyMode.EXPLICIT, "http://proxy.example:3128?x=1"),
        (ProxyMode.EXPLICIT, "socks5://proxy.example:1080"),
        (ProxyMode.EXPLICIT, "http://proxy.example:99999"),
        (ProxyMode.EXPLICIT, "http://proxy example:3128"),
        ("env", None),
    ):
        with pytest.raises(ValueError):
            NetworkSettings(mode, url)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "factory",
    [
        lambda: InspireSettings(timeout_s=0.5),
        lambda: InspireSettings(enabled="yes"),  # type: ignore[arg-type]
        lambda: ArxivSettings(timeout_s=31),
        lambda: ArxivSettings(min_interval_s=2.0),
        lambda: ArxivSettings(min_interval_s=True),  # type: ignore[arg-type]
        lambda: HepdataSettings(timeout_s=float("nan")),
        lambda: LocalLibrarySettings(True, "relative/path"),
        lambda: LocalLibrarySettings(True, ""),
        lambda: LocalLibrarySettings(True, "/abs\x00path"),
    ],
)
def test_provider_settings_refusals(factory) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError):
        factory()


def test_local_root_accepts_home_expansion() -> None:
    assert LocalLibrarySettings(True, "~/asca-library").root == "~/asca-library"


def test_mcp_server_settings_good_examples() -> None:
    server = http_server()
    assert server.provider_id == "mcp:chatlas"
    assert stdio_server().provider_id == "mcp:gitlab"
    loopback = http_server(url="http://127.0.0.1:8123/mcp", allow_insecure_loopback=True)
    assert loopback.url
    public = http_server(access_class=AccessClass.PUBLIC, access_conditions=None)
    assert public.access_class is AccessClass.PUBLIC


@pytest.mark.parametrize(
    "changes",
    [
        {"server_id": "ChatLAS"},
        {"enabled": None},
        {"transport": "stdio"},
        {"allow_private_network": 0},
        {"url": None},
        {"url": "http://chatlas.example/mcp"},
        {"command": "/bin/sh"},
        {"args": ("--x",)},
        {"env": (("A", "ASCA_X"),)},
        {"token_env": "GITHUB_TOKEN"},
        {"access_conditions": None},
        {"access_class": AccessClass.PUBLIC},
        {"access_conditions": "x" * 2001},
        {"access_conditions": "bad\x1b"},
        {"max_query_access": "internal"},
        {"authority_ceiling": SourceAuthority.PUBLISHED},
        {"authority_ceiling": SourceAuthority.APPROVED_INTERNAL},
        {"result_kind": "documents"},
        {"search_tool": "bad tool"},
        {"search_query_arg": "1query"},
        {"search_limit_arg": "bad-arg"},
        {"fetch_tool": ""},
        {"fetch_id_arg": "id!"},
        {"expected_tools_sha256": "ABC"},
        {"timeout_s": 60.0},
    ],
)
def test_mcp_http_settings_refusals(changes: dict[str, object]) -> None:
    with pytest.raises((ValueError, UnsafeUrl)):
        http_server(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"url": "https://chatlas.example/mcp"},
        {"token_env": "ASCA_TOKEN"},
        {"command": None},
        {"command": "relative/cmd"},
        {"command": "/bin/\x00sh"},
        {"args": ["--read-only"]},
        {"args": ("a",) * 33},
        {"args": ("x" * 1001,)},
        {"args": ("a\x00",)},
        {"env": [("GITLAB_TOKEN", "ASCA_X")]},
        {"env": (("A", "ASCA_X"),) * 17},
        {"env": (("GITLAB_TOKEN",),)},
        {"env": (("LD_PRELOAD", "ASCA_X"),)},
        {"env": (("DYLD_INSERT_LIBRARIES", "ASCA_X"),)},
        {"env": (("PYTHONPATH", "ASCA_X"),)},
        {"env": (("GITLAB_TOKEN", "HOME"),)},
        {"env": (("lower", "ASCA_X"),)},
    ],
)
def test_mcp_stdio_settings_refusals(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        stdio_server(**changes)


def test_knowledge_settings_validation() -> None:
    local = LocalLibrarySettings(False, "/srv/asca-library")
    settings = KnowledgeSettings(
        precedence=("local", "mcp:chatlas", "inspire"), local=local, mcp=(http_server(),)
    )
    assert settings.precedence[0] == "local"
    for changes in (
        {"precedence": ("local",)},
        {"precedence": ("inspire", "inspire")},
        {"precedence": ["inspire"]},
        {"precedence": ("mcp:other",)},
        {"precedence": ("Bad",)},
        {"mcp": (http_server(), http_server())},
        {"mcp": [http_server()]},
        {"mcp": tuple(http_server(server_id=f"s{i}") for i in range(17))},
        {"network": None},
        {"inspire": ArxivSettings()},
        {"local": "/srv"},
    ):
        with pytest.raises(ValueError):
            replace(DEFAULT_SETTINGS, **changes)  # type: ignore[arg-type]
