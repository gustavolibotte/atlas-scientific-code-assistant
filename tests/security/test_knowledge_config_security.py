"""Security negative tests for the knowledge configuration (a code-execution input)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from asca.infrastructure.knowledge.config import (
    KnowledgeConfigError,
    check_command,
    load_settings,
    parse_settings,
)
from asca.infrastructure.knowledge.settings import DEFAULT_SETTINGS

pytestmark = pytest.mark.security

HEADER = 'format = "asca-knowledge/1"\n'
CANARY = "canary-secret-value-5b1d"


def write_config(path: Path, text: str, mode: int = 0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def executable(path: Path, mode: int = 0o755) -> Path:
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(mode)
    return path


def stdio_config(command: str, **extra: str) -> str:
    keys = {
        "enabled": "true",
        "transport": '"stdio"',
        "command": f'"{command}"',
        "access_class": '"internal"',
        "access_conditions": '"Synthetic"',
        **extra,
    }
    return HEADER + "[mcp.srv]\n" + "".join(f"{key} = {value}\n" for key, value in keys.items())


def http_config(**extra: str) -> str:
    keys = {
        "enabled": "true",
        "transport": '"streamable_http"',
        "url": '"https://mcp.example.org/mcp"',
        "access_class": '"public"',
        **extra,
    }
    return HEADER + "[mcp.srv]\n" + "".join(f"{key} = {value}\n" for key, value in keys.items())


def refused(path: Path, environ: dict[str, str] | None = None, **kwargs: object) -> str:
    with pytest.raises(KnowledgeConfigError) as raised:
        load_settings(str(path), environ or {}, **kwargs)  # type: ignore[arg-type]
    assert str(path) not in str(raised.value)
    assert all(str(path) not in detail for detail in raised.value.details)
    return raised.value.code


def invalid_details(text: str, environ: dict[str, str] | None = None) -> tuple[str, ...]:
    with pytest.raises(KnowledgeConfigError) as raised:
        parse_settings(text.encode("utf-8"), environ or {"HOME": "/home/tester"})
    assert raised.value.code == "config_invalid"
    assert raised.value.__cause__ is None
    return raised.value.details


@pytest.mark.parametrize("mode", [0o620, 0o602, 0o666, 0o664])
def test_group_or_world_writable_file_is_refused(tmp_path: Path, mode: int) -> None:
    path = write_config(tmp_path / "k.toml", HEADER, mode)
    assert refused(path) == "config_unsafe_file"


def test_file_owned_by_another_user_is_refused(tmp_path: Path) -> None:
    path = write_config(tmp_path / "k.toml", HEADER)

    def foreign_stat(fd: int) -> os.stat_result:
        real = os.fstat(fd)
        fields = list(real[:10])
        fields[4] = real.st_uid + 4242  # st_uid
        return os.stat_result(fields)

    assert refused(path, _stat=foreign_stat) == "config_unsafe_file"


def test_symlinked_config_is_never_followed(tmp_path: Path) -> None:
    target = write_config(tmp_path / "real.toml", HEADER)
    link = tmp_path / "k.toml"
    link.symlink_to(target)
    assert refused(link) == "config_unsafe_file"


def test_directory_and_unreadable_paths_are_refused(tmp_path: Path) -> None:
    folder = tmp_path / "k.toml"
    folder.mkdir()
    assert refused(folder) == "config_unsafe_file"
    not_dir = write_config(tmp_path / "file", HEADER)
    assert refused(not_dir / "k.toml") == "config_unsafe_file"


def test_group_writable_parent_with_a_stdio_server_is_refused(tmp_path: Path) -> None:
    command = executable(tmp_path / "server")
    folder = tmp_path / "shared"
    path = write_config(folder / "k.toml", stdio_config(str(command)))
    folder.chmod(0o775)
    assert refused(path) == "config_unsafe_directory"
    folder.chmod(0o700)
    settings = load_settings(str(path), {})
    assert settings.mcp[0].command == os.path.realpath(command)


def test_group_writable_parent_without_stdio_is_accepted(tmp_path: Path) -> None:
    folder = tmp_path / "shared"
    path = write_config(folder / "k.toml", http_config())
    folder.chmod(0o775)
    assert load_settings(str(path), {}).mcp[0].provider_id == "mcp:srv"


@pytest.mark.parametrize("key", ["token", "password", "api_key", "bearer"])
def test_inline_secrets_are_refused_without_echo(tmp_path: Path, key: str) -> None:
    path = write_config(tmp_path / "k.toml", http_config(**{key: f'"{CANARY}"'}))
    with pytest.raises(KnowledgeConfigError) as raised:
        load_settings(str(path), {})
    error = raised.value
    assert error.code == "config_invalid"
    assert error.details == (f"mcp.srv.{key}: extra_forbidden",)
    assert CANARY not in repr(error) + repr(error.details) + str(error)


@pytest.mark.parametrize(
    ("extra", "detail"),
    [
        ({"token_env": '"GITHUB_TOKEN"'}, "mcp.token_env: invalid"),
        ({"token_env": '"ASCA_lower"'}, "mcp.token_env: invalid"),
        ({"url": '"http://mcp.example.org/mcp"'}, "url: scheme"),
        ({"url": '"https://user:pw@mcp.example.org/mcp"'}, "url: userinfo"),
        ({"url": '"https://mcp.example.org/mcp?token=x"'}, "url: query"),
        ({"url": '"https://mcp.example.org/mcp#frag"'}, "url: fragment"),
        (
            {"url": '"http://127.0.0.1:8000/mcp"'},
            "url: scheme",
        ),
    ],
)
def test_unsafe_http_server_settings_are_refused(extra: dict[str, str], detail: str) -> None:
    details = invalid_details(http_config(**extra))
    assert details == (detail,)
    for value in extra.values():
        assert value.strip('"') not in repr(details)


def test_insecure_loopback_needs_the_explicit_flag() -> None:
    text = http_config(url='"http://127.0.0.1:8000/mcp"', allow_insecure_loopback="true")
    settings = parse_settings(text.encode(), {})
    assert settings.mcp[0].allow_insecure_loopback is True


@pytest.mark.parametrize(
    ("env", "detail"),
    [
        ('{ GITLAB_TOKEN = "HOME" }', "mcp.env: invalid"),
        ('{ GITLAB_TOKEN = "GITHUB_TOKEN" }', "mcp.env: invalid"),
        ('{ LD_PRELOAD = "ASCA_X" }', "mcp.env: invalid"),
        ('{ DYLD_INSERT_LIBRARIES = "ASCA_X" }', "mcp.env: invalid"),
        ('{ PYTHONPATH = "ASCA_X" }', "mcp.env: invalid"),
        ('{ lower = "ASCA_X" }', "mcp.env: invalid"),
    ],
)
def test_unsafe_child_environment_is_refused(tmp_path: Path, env: str, detail: str) -> None:
    command = executable(tmp_path / "server")
    assert invalid_details(stdio_config(str(command), env=env)) == (detail,)


def test_relative_command_is_refused() -> None:
    details = invalid_details(stdio_config("bin/server"))
    assert details == ("mcp.srv.command: not_absolute",)
    assert invalid_details(stdio_config("~other/server")) == ("mcp.srv.command: not_absolute",)


@pytest.mark.parametrize("mode", [0o757, 0o775, 0o644])
def test_writable_or_non_executable_command_is_refused(tmp_path: Path, mode: int) -> None:
    command = executable(tmp_path / "server", mode)
    assert invalid_details(stdio_config(str(command))) == ("mcp.srv.command: unsafe_command",)


def test_missing_or_directory_command_is_refused(tmp_path: Path) -> None:
    for command in (tmp_path / "absent", tmp_path):
        assert invalid_details(stdio_config(str(command))) == ("mcp.srv.command: unsafe_command",)


def test_command_symlink_resolves_to_the_checked_target(tmp_path: Path) -> None:
    target = executable(tmp_path / "server")
    writable = executable(tmp_path / "writable", 0o777)
    link = tmp_path / "link"
    link.symlink_to(writable)
    assert invalid_details(stdio_config(str(link))) == ("mcp.srv.command: unsafe_command",)
    good = tmp_path / "good-link"
    good.symlink_to(target)
    assert check_command(str(good), {}, "c") == os.path.realpath(target)


def test_home_relative_command_is_expanded(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / "bin").mkdir(parents=True)
    command = executable(home / "bin" / "server")
    assert check_command("~/bin/server", {"HOME": str(home)}, "c") == os.path.realpath(command)


def test_default_path_is_never_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "untrusted-checkout"
    command = executable(tmp_path / "server")
    write_config(project / ".asca" / "knowledge.toml", stdio_config(str(command)))
    write_config(project / "knowledge.toml", stdio_config(str(command)))
    write_config(project / "asca" / "knowledge.toml", stdio_config(str(command)))
    monkeypatch.chdir(project)
    home = tmp_path / "home"
    home.mkdir()
    for environ in (
        {"HOME": str(home)},
        {"HOME": str(home), "XDG_CONFIG_HOME": "."},
        {"HOME": str(home), "XDG_CONFIG_HOME": ""},
        {"HOME": "."},
        {},
    ):
        assert load_settings(None, environ) == DEFAULT_SETTINGS


def test_validation_errors_never_echo_values(tmp_path: Path) -> None:
    text = http_config(
        url=f'"https://{CANARY}.example.org/mcp?x={CANARY}"',
        search_tool=f'"{CANARY}!"',
    )
    path = write_config(tmp_path / "k.toml", text)
    with pytest.raises(KnowledgeConfigError) as raised:
        load_settings(str(path), {})
    rendered = str(raised.value) + repr(raised.value.details)
    assert CANARY not in rendered
    with pytest.raises(KnowledgeConfigError) as raised:
        parse_settings(f'{HEADER}[providers.inspire]\nenabled = "{CANARY}"\n'.encode(), {})
    assert CANARY not in repr(raised.value.details)
    assert raised.value.details == ("providers.inspire.enabled: bool_type",)


def test_file_growing_after_fstat_is_still_capped(tmp_path: Path) -> None:
    path = write_config(tmp_path / "k.toml", HEADER + "#" * 70_000)

    def shrinking_stat(fd: int) -> os.stat_result:
        fields = list(os.fstat(fd)[:10])
        fields[6] = 10  # st_size claims a tiny file
        return os.stat_result(fields)

    assert refused(path, _stat=shrinking_stat) == "config_too_large"


def test_stat_failure_is_refused(tmp_path: Path) -> None:
    path = write_config(tmp_path / "k.toml", HEADER)

    def failing_stat(fd: int) -> os.stat_result:
        raise OSError("simulated")

    assert refused(path, _stat=failing_stat) == "config_unsafe_file"
