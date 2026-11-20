"""Knowledge configuration: path resolution, schema and mapping to settings."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from asca.domain.provenance import AccessClass, SourceAuthority
from asca.infrastructure.knowledge.config import (
    CONFIG_MAX_BYTES,
    KnowledgeConfigError,
    default_config_path,
    effective_precedence,
    load_settings,
    parse_settings,
    resolve_config_path,
)
from asca.infrastructure.knowledge.settings import (
    DEFAULT_SETTINGS,
    KnowledgeSettings,
    LocalLibrarySettings,
    McpResultKind,
    McpTransport,
    NetworkSettings,
    ProxyMode,
)

pytestmark = pytest.mark.contract

HEADER = 'format = "asca-knowledge/1"\n'


def write_config(path: Path, text: str, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def full_example(command: Path) -> str:
    return f"""
format = "asca-knowledge/1"
[federation]
precedence = ["inspire", "arxiv", "hepdata", "local", "mcp:chatlas"]
[network]
proxy = "env"
[providers.inspire]
enabled = true
timeout_s = 10.0
[providers.arxiv]
enabled = true
timeout_s = 15.0
min_interval_s = 3.0
[providers.hepdata]
enabled = true
timeout_s = 10.0
[providers.local]
enabled = false
root = "~/asca-library"
timeout_s = 5.0
[mcp.chatlas]
enabled = false
transport = "streamable_http"
url = "https://chatlas.example.org/mcp"
token_env = "ASCA_CHATLAS_TOKEN"
allow_private_network = false
allow_insecure_loopback = false
access_class = "internal"
access_conditions = "ATLAS members via CERN SSO"
max_query_access = "internal"
authority_ceiling = "working_material"
result_kind = "documents"
search_tool = "search"
search_query_arg = "query"
fetch_tool = "fetch"
fetch_id_arg = "id"
timeout_s = 20.0
[mcp.gitlab]
enabled = false
transport = "stdio"
command = "{command}"
args = ["--read-only"]
env = {{ GITLAB_TOKEN = "ASCA_CERNGITLAB_TOKEN" }}
access_class = "internal"
access_conditions = "CERN GitLab project permissions"
"""


def environ_for(tmp_path: Path, **extra: str) -> dict[str, str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return {"HOME": str(home), **extra}


def invalid(text: str, environ: dict[str, str] | None = None) -> KnowledgeConfigError:
    with pytest.raises(KnowledgeConfigError) as raised:
        parse_settings(
            text.encode("utf-8"), {"HOME": "/home/tester"} if environ is None else environ
        )
    assert raised.value.code == "config_invalid"
    return raised.value


def test_defaults_when_the_default_file_is_absent(tmp_path: Path) -> None:
    settings = load_settings(None, environ_for(tmp_path))
    assert settings == DEFAULT_SETTINGS
    assert settings.inspire.enabled and settings.arxiv.enabled and settings.hepdata.enabled
    assert settings.local is None and settings.mcp == ()


def test_defaults_without_a_home(tmp_path: Path) -> None:
    assert default_config_path({}) is None
    assert default_config_path({"HOME": "relative/home"}) is None
    assert load_settings(None, {}) == DEFAULT_SETTINGS


def test_default_path_uses_xdg_then_home(tmp_path: Path) -> None:
    assert default_config_path({"HOME": "/h"}) == "/h/.config/asca/knowledge.toml"
    assert default_config_path({"HOME": "/h", "XDG_CONFIG_HOME": "/x"}) == (
        "/x/asca/knowledge.toml"
    )
    # XDG requires an absolute path; a relative value is ignored, never the working dir.
    assert default_config_path({"HOME": "/h", "XDG_CONFIG_HOME": "rel"}) == (
        "/h/.config/asca/knowledge.toml"
    )


def test_resolution_order(tmp_path: Path) -> None:
    env = {"HOME": "/h", "ASCA_KNOWLEDGE_CONFIG": "/env.toml"}
    assert resolve_config_path("/arg.toml", env) == ("/arg.toml", True)
    assert resolve_config_path(None, env) == ("/env.toml", True)
    assert resolve_config_path(None, {"HOME": "/h"}) == ("/h/.config/asca/knowledge.toml", False)


def test_xdg_default_file_is_loaded(tmp_path: Path) -> None:
    xdg = tmp_path / "xdg"
    write_config(xdg / "asca" / "knowledge.toml", HEADER + "[providers.hepdata]\nenabled = false\n")
    settings = load_settings(None, environ_for(tmp_path, XDG_CONFIG_HOME=str(xdg)))
    assert settings.hepdata.enabled is False


def test_environment_path_is_loaded(tmp_path: Path) -> None:
    path = write_config(tmp_path / "k.toml", HEADER + '[network]\nproxy = "none"\n')
    settings = load_settings(None, environ_for(tmp_path, ASCA_KNOWLEDGE_CONFIG=str(path)))
    assert settings.network == NetworkSettings(ProxyMode.NONE)


@pytest.mark.parametrize("variable", ["argument", "environment"])
def test_explicit_missing_path_is_an_error(tmp_path: Path, variable: str) -> None:
    missing = str(tmp_path / "absent.toml")
    env = environ_for(tmp_path)
    with pytest.raises(KnowledgeConfigError) as raised:
        if variable == "argument":
            load_settings(missing, env)
        else:
            load_settings(None, {**env, "ASCA_KNOWLEDGE_CONFIG": missing})
    assert raised.value.code == "config_missing"
    assert missing not in str(raised.value)


def test_full_example_parses(tmp_path: Path) -> None:
    command = executable(tmp_path / "cerngitlab-mcp")
    path = write_config(tmp_path / "knowledge.toml", full_example(command))
    env = environ_for(tmp_path)
    settings = load_settings(str(path), env)
    assert settings.precedence == ("inspire", "arxiv", "hepdata", "local", "mcp:chatlas")
    assert settings.network.proxy_mode is ProxyMode.ENV
    assert settings.arxiv.min_interval_s == 3.0
    assert settings.local == LocalLibrarySettings(False, env["HOME"] + "/asca-library", 5.0)
    chatlas, gitlab = settings.mcp
    assert chatlas.provider_id == "mcp:chatlas"
    assert chatlas.transport is McpTransport.STREAMABLE_HTTP
    assert chatlas.url == "https://chatlas.example.org/mcp"
    assert chatlas.token_env == "ASCA_CHATLAS_TOKEN"
    assert chatlas.access_class is AccessClass.INTERNAL
    assert chatlas.max_query_access is AccessClass.INTERNAL
    assert chatlas.authority_ceiling is SourceAuthority.WORKING_MATERIAL
    assert chatlas.result_kind is McpResultKind.DOCUMENTS
    assert (chatlas.fetch_tool, chatlas.fetch_id_arg) == ("fetch", "id")
    assert gitlab.transport is McpTransport.STDIO
    assert gitlab.command == os.path.realpath(command)
    assert gitlab.args == ("--read-only",)
    assert gitlab.env == (("GITLAB_TOKEN", "ASCA_CERNGITLAB_TOKEN"),)
    assert gitlab.max_query_access is AccessClass.INTERNAL
    assert (gitlab.search_tool, gitlab.search_query_arg, gitlab.fetch_tool) == (
        "search",
        "query",
        None,
    )
    assert effective_precedence(settings) == (
        "inspire",
        "arxiv",
        "hepdata",
        "local",
        "mcp:chatlas",
        "mcp:gitlab",
    )


def test_minimal_file_keeps_defaults() -> None:
    assert parse_settings(HEADER.encode(), {}) == KnowledgeSettings()


def test_generated_server_and_explicit_query_access() -> None:
    settings = parse_settings(
        (
            HEADER
            + """
[mcp.helper]
enabled = true
transport = "streamable_http"
url = "https://helper.example.org/mcp"
access_class = "public"
max_query_access = "restricted"
authority_ceiling = "automated_inference"
result_kind = "generated"
search_limit_arg = "limit"
expected_tools_sha256 = "%s"
"""
            % ("a" * 64)
        ).encode(),
        {},
    )
    (server,) = settings.mcp
    assert server.access_conditions is None
    assert server.max_query_access is AccessClass.RESTRICTED
    assert server.authority_ceiling is SourceAuthority.AUTOMATED_INFERENCE
    assert server.result_kind is McpResultKind.GENERATED
    assert server.search_limit_arg == "limit"
    assert server.expected_tools_sha256 == "a" * 64


@pytest.mark.parametrize(
    ("proxy", "expected"),
    [
        ("env", NetworkSettings(ProxyMode.ENV)),
        ("none", NetworkSettings(ProxyMode.NONE)),
        (
            "http://proxy.example.org:3128",
            NetworkSettings(ProxyMode.EXPLICIT, "http://proxy.example.org:3128"),
        ),
    ],
)
def test_proxy_modes(proxy: str, expected: NetworkSettings) -> None:
    settings = parse_settings(f'{HEADER}[network]\nproxy = "{proxy}"\n'.encode(), {})
    assert settings.network == expected


@pytest.mark.parametrize(
    "proxy", ["socks5://p.example.org:1080", "http://user:pw@p.example.org:3128", "http://p"]
)
def test_invalid_proxy_is_refused(proxy: str) -> None:
    error = invalid(f'{HEADER}[network]\nproxy = "{proxy}"\n')
    assert error.details == ("network.proxy_url: invalid",)
    assert proxy not in repr(error.details)


def test_effective_precedence_without_configured_precedence() -> None:
    assert effective_precedence(DEFAULT_SETTINGS) == ("inspire", "arxiv", "hepdata")
    local = KnowledgeSettings(
        precedence=("local", "arxiv"), local=LocalLibrarySettings(True, "/lib")
    )
    assert effective_precedence(local) == ("local", "arxiv", "inspire", "hepdata")


@pytest.mark.parametrize(
    "precedence",
    [
        '["inspire", "inspire"]',
        '["unknown"]',
        '["local"]',
        '["mcp:absent"]',
        '["Inspire"]',
    ],
)
def test_precedence_validation(precedence: str) -> None:
    error = invalid(f"{HEADER}[federation]\nprecedence = {precedence}\n")
    assert error.details == ("precedence: invalid",)


def http_server(**extra: str) -> str:
    keys = {
        "enabled": "true",
        "transport": '"streamable_http"',
        "url": '"https://mcp.example.org/mcp"',
        "access_class": '"public"',
        **extra,
    }
    return HEADER + "[mcp.srv]\n" + "".join(f"{key} = {value}\n" for key, value in keys.items())


def stdio_server(command: Path, **extra: str) -> str:
    keys = {
        "enabled": "true",
        "transport": '"stdio"',
        "command": f'"{command}"',
        "access_class": '"internal"',
        "access_conditions": '"Synthetic"',
        **extra,
    }
    return HEADER + "[mcp.srv]\n" + "".join(f"{key} = {value}\n" for key, value in keys.items())


@pytest.mark.parametrize("key", ["command", "args", "env"])
def test_stdio_keys_are_forbidden_on_http(key: str) -> None:
    value = {"command": '"/bin/true"', "args": "[]", "env": "{}"}[key]
    error = invalid(http_server(**{key: value}))
    assert error.details == (f"mcp.srv.{key}: other_transport",)


@pytest.mark.parametrize(
    "key", ["url", "token_env", "allow_private_network", "allow_insecure_loopback"]
)
def test_http_keys_are_forbidden_on_stdio(tmp_path: Path, key: str) -> None:
    command = executable(tmp_path / "server")
    value = {
        "url": '"https://mcp.example.org/mcp"',
        "token_env": '"ASCA_TOKEN"',
        "allow_private_network": "false",
        "allow_insecure_loopback": "false",
    }[key]
    error = invalid(stdio_server(command, **{key: value}))
    assert error.details == (f"mcp.srv.{key}: other_transport",)


def test_stdio_without_command_is_refused() -> None:
    text = (
        HEADER
        + '[mcp.srv]\nenabled = true\ntransport = "stdio"\naccess_class = "internal"\n'
        + 'access_conditions = "x"\n'
    )
    assert invalid(text).details == ("mcp.srv.command: missing",)


def test_http_without_url_is_refused() -> None:
    text = HEADER + '[mcp.srv]\nenabled = true\ntransport = "streamable_http"\n'
    text += 'access_class = "public"\n'
    assert invalid(text).details == ("mcp.transport: invalid",)


def test_arxiv_min_interval_below_three_seconds_is_refused() -> None:
    error = invalid(f"{HEADER}[providers.arxiv]\nmin_interval_s = 2.0\n")
    assert error.details == ("arxiv.min_interval_s: invalid",)


@pytest.mark.parametrize("ceiling", ["published", "approved_internal", "verified_implementation"])
def test_mcp_ceiling_above_working_material_is_refused(ceiling: str) -> None:
    error = invalid(http_server(authority_ceiling=f'"{ceiling}"'))
    assert error.details == ("mcp.srv.authority_ceiling: literal_error",)


def test_mcp_access_class_is_required() -> None:
    text = HEADER + '[mcp.srv]\nenabled = true\ntransport = "streamable_http"\n'
    text += 'url = "https://mcp.example.org/mcp"\n'
    assert invalid(text).details == ("mcp.srv.access_class: missing",)


def test_mcp_internal_without_conditions_is_refused() -> None:
    error = invalid(http_server(access_class='"internal"'))
    assert error.details == ("mcp.access_conditions: invalid",)


@pytest.mark.parametrize(
    ("text", "detail"),
    [
        ("", "format: missing"),
        ('format = "asca-knowledge/2"\n', "format: literal_error"),
        (HEADER + "[providers.inspire]\ntimeout_s = 60.0\n", "inspire.timeout_s: invalid"),
        (HEADER + "[providers.inspire]\ntimeout_s = inf\n", "providers.inspire.timeout_s"),
        (HEADER + '[providers.inspire]\nenabled = "yes"\n', "providers.inspire.enabled"),
        (HEADER + "[providers.inspire]\nextra = 1\n", "providers.inspire.extra: extra_forbidden"),
        (HEADER + "[unknown]\n", "unknown: extra_forbidden"),
        (HEADER + '[providers.local]\nroot = "/lib"\n', "providers.local.enabled: missing"),
        (HEADER + "[mcp.Bad_Id]\n", "mcp.Bad_Id.enabled: missing"),
        (HEADER + "format = 1\n", "toml: syntax"),
    ],
)
def test_schema_errors(text: str, detail: str) -> None:
    error = invalid(text)
    assert any(item.startswith(detail) for item in error.details), error.details


def test_invalid_server_id_is_refused() -> None:
    error = invalid(http_server().replace("[mcp.srv]", "[mcp.Bad_Id]"))
    assert error.details == ("mcp.server_id: invalid",)


def test_too_many_mcp_servers_is_refused() -> None:
    body = "".join(
        f'[mcp.s{index}]\nenabled = false\ntransport = "streamable_http"\n'
        f'url = "https://mcp.example.org/mcp"\naccess_class = "public"\n'
        for index in range(17)
    )
    error = invalid(HEADER + body)
    assert error.details == ("mcp: too_long",)


def test_local_root_expansion(tmp_path: Path) -> None:
    text = HEADER + '[providers.local]\nenabled = true\nroot = "~"\n'
    settings = parse_settings(text.encode(), {"HOME": "/home/tester"})
    assert settings.local == LocalLibrarySettings(True, "/home/tester")
    absolute = HEADER + '[providers.local]\nenabled = true\nroot = "/srv/library"\n'
    settings = parse_settings(absolute.encode(), {})
    assert settings.local is not None and settings.local.root == "/srv/library"


@pytest.mark.parametrize(
    ("root", "environ", "detail"),
    [
        ("~other/library", {"HOME": "/home/tester"}, "providers.local.root: not_absolute"),
        ("~/library", {}, "providers.local.root: home_unavailable"),
        ("relative/library", {"HOME": "/home/tester"}, "local.root: invalid"),
    ],
)
def test_local_root_refusals(root: str, environ: dict[str, str], detail: str) -> None:
    text = f'{HEADER}[providers.local]\nenabled = true\nroot = "{root}"\n'
    assert invalid(text, environ).details == (detail,)


def test_non_utf8_and_too_large_files(tmp_path: Path) -> None:
    error = invalid("")
    assert error.code == "config_invalid"
    with pytest.raises(KnowledgeConfigError) as raised:
        parse_settings(HEADER.encode() + b"# \xff\n", {})
    assert raised.value.details == ("toml: syntax",)
    big = write_config(tmp_path / "big.toml", HEADER + "#" * CONFIG_MAX_BYTES)
    with pytest.raises(KnowledgeConfigError) as raised:
        load_settings(str(big), {})
    assert raised.value.code == "config_too_large"


def test_error_code_vocabulary() -> None:
    with pytest.raises(ValueError, match="unknown configuration error code"):
        KnowledgeConfigError("anything")
    error = KnowledgeConfigError("config_invalid", ("a: b",))
    assert str(error) == "knowledge configuration error: config_invalid"
    assert error.details == ("a: b",)
