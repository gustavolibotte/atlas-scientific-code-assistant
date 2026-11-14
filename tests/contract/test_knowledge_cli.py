"""Knowledge CLI over an injected federation of fake providers, and over the real factory
with replayed fixtures (never the network)."""

from __future__ import annotations

import io
import json
import logging
import runpy
import sys
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from knowledge_adapters import EXIT_QUERY
from knowledge_contract import (
    FakeProvider,
    fetch_result,
    identity,
    make_candidate,
    make_descriptor,
    related,
)
from knowledge_exit import GOLDEN, exit_cli_json, exit_transport, run_cli

from asca.application.demo import FixedClock
from asca.application.knowledge.federation import FederationPolicy, FederationService
from asca.application.knowledge.models import (
    HealthState,
    ProviderError,
    ProviderErrorKind,
    ProviderHealth,
    ProviderKind,
    SearchResult,
)
from asca.application.ports import Clock
from asca.domain.provenance import AccessClass, SourceAuthority
from asca.infrastructure.knowledge import __main__ as cli
from asca.infrastructure.knowledge.settings import KnowledgeSettings

pytestmark = pytest.mark.contract

NOW = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
CANARY = "canary-cli-value-91c2"


class Harness:
    """Builds a federation from fixed fake providers and records how it was built."""

    def __init__(self, providers: Sequence[FakeProvider], disabled: Sequence[str] = ()) -> None:
        self.providers = list(providers)
        self.disabled = [make_descriptor(ProviderKind(kind)) for kind in disabled]
        self.builds: list[tuple[KnowledgeSettings, bool]] = []

    def __call__(
        self, settings: KnowledgeSettings, *, live: bool, clock: Clock
    ) -> FederationService:
        assert clock.now().tzinfo is not None
        self.builds.append((settings, live))
        return FederationService(
            self.providers, FederationPolicy(live=live), disabled=self.disabled
        )

    def run(self, *argv: str, environ: dict[str, str] | None = None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(
            list(argv),
            build=self,
            environ={} if environ is None else environ,
            clock=FixedClock(NOW),
            stdout=out,
            stderr=err,
        )
        return code, out.getvalue(), err.getvalue()


def inspire_ok() -> FakeProvider:
    candidate = make_candidate(
        ProviderKind.INSPIRE,
        "1920956",
        pids=[identity("doi:10.5555/asca-test.1"), identity("inspire:1920956")],
        refereed=True,
        title="Refereed synthetic paper",
    )
    return FakeProvider(
        make_descriptor(ProviderKind.INSPIRE),
        search_outcome=SearchResult((candidate,), 17, 0),
        fetch_outcome=fetch_result(candidate, "Synthetic abstract text.\n"),
    )


def arxiv_ok() -> FakeProvider:
    candidate = make_candidate(
        ProviderKind.ARXIV,
        "2109.05124v2",
        pids=[identity("doi:10.5555/asca-test.1"), identity("arxiv:2109.05124")],
    )
    return FakeProvider(
        make_descriptor(ProviderKind.ARXIV), search_outcome=SearchResult((candidate,), 4, 0)
    )


def hepdata_blocked() -> FakeProvider:
    return FakeProvider(
        make_descriptor(ProviderKind.HEPDATA),
        search_outcome=ProviderError(ProviderErrorKind.BLOCKED, "bot_challenge", 403),
        health_outcome=ProviderHealth(
            "hepdata",
            HealthState.UNAVAILABLE,
            ProviderError(ProviderErrorKind.BLOCKED, "bot_challenge", 403),
        ),
    )


def local_ok(text: str = "Synthetic local text.\n") -> FakeProvider:
    candidate = make_candidate(
        ProviderKind.LOCAL,
        "notes/a.md",
        pids=[identity("arxiv:2109.05124"), related("local_document:notes/a.md")],
        access_class=AccessClass.INTERNAL,
        declared_authority=SourceAuthority.WORKING_MATERIAL,
        title="Synthetic local note",
    )
    return FakeProvider(
        make_descriptor(ProviderKind.LOCAL),
        search_outcome=SearchResult((candidate,), 1, 0),
        fetch_outcome=fetch_result(candidate, text),
    )


def test_search_json_format_and_exit_zero() -> None:
    harness = Harness([inspire_ok(), arxiv_ok()])
    code, out, err = harness.run("search", "  liquid argon  ", "--live", "--limit", "3")
    assert (code, err) == (0, "")
    assert harness.builds[0][1] is True
    assert out.endswith("}\n")
    view = json.loads(out)
    assert out == json.dumps(view, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    assert view["format"] == "asca-knowledge-search/1"
    assert view["query"] == {"text": "liquid argon", "limit": 3, "access_class": "public"}
    assert view["complete"] is True
    assert view["providers"][0] == {
        "id": "inspire",
        "kind": "inspire",
        "status": "ok",
        "returned": 1,
        "dropped_items": 0,
        "total_reported": 17,
        "error": None,
    }
    (group,) = view["groups"]
    assert group["key"] == "doi:10.5555/asca-test.1"
    assert group["identity_pids"] == [
        "doi:10.5555/asca-test.1",
        "arxiv:2109.05124",
        "inspire:1920956",
    ]
    assert group["flags"] == []
    assert group["effective_access_class"] == "public"
    inspire, arxiv = group["members"]
    assert inspire["provider"] == "inspire"
    assert inspire["suggestion"] == {
        "authority": "published",
        "letter": "A",
        "rule": "inspire.refereed/1",
        "basis": "Refereed INSPIRE record 1920956 lists DOI 10.5555/asca-test.1.",
    }
    assert inspire["retrieved_at"] == "2026-11-14T10:00:00Z"
    assert inspire["pids"][0] == {
        "pid": "doi:10.5555/asca-test.1",
        "role": "identity",
        "origin": "curated_link",
    }
    assert inspire["version"] == {"kind": "record_snapshot", "label": "inspire:1920956@2026-11-01"}
    assert inspire["licenses"] == [{"identifier": "CC0-1.0", "url": None, "scope": "metadata"}]
    assert set(inspire) == {
        "provider",
        "native_id",
        "rank",
        "title",
        "title_truncated",
        "authors",
        "author_count",
        "issued",
        "version",
        "pids",
        "landing_url",
        "access_class",
        "access_conditions",
        "facts",
        "suggestion",
        "content",
        "licenses",
        "snippet",
        "retrieved_at",
    }
    assert arxiv["suggestion"]["letter"] == "D"
    assert "elapsed_ms" not in out


def test_timings_add_elapsed_ms() -> None:
    code, out, _ = Harness([inspire_ok()]).run("search", "argon", "--live", "--timings")
    assert code == 0
    assert isinstance(json.loads(out)["providers"][0]["elapsed_ms"], int)


def test_without_live_network_providers_are_never_called() -> None:
    providers = [inspire_ok(), arxiv_ok(), hepdata_blocked()]
    harness = Harness(providers)
    code, out, err = harness.run("search", "argon")
    assert code == 4
    assert err == "note: network providers need --live\n"
    assert harness.builds[0][1] is False
    assert all(provider.calls == [] for provider in providers)
    view = json.loads(out)
    assert [(item["status"], item["error"]["code"]) for item in view["providers"]] == [
        ("skipped", "live_disabled")
    ] * 3
    assert view["groups"] == []
    assert view["complete"] is False


def test_exit_three_when_some_providers_fail() -> None:
    code, out, _ = Harness([inspire_ok(), hepdata_blocked(), local_ok()]).run(
        "search", "argon", "--live"
    )
    assert code == 3
    view = json.loads(out)
    assert view["providers"][1]["error"] == {
        "kind": "blocked",
        "code": "bot_challenge",
        "http_status": 403,
        "retry_after_s": None,
    }


def test_local_only_without_live_is_partial_and_notes_live() -> None:
    harness = Harness([inspire_ok(), local_ok()])
    code, _, err = harness.run("search", "argon")
    assert code == 3
    assert "need --live" in err


def test_local_provider_alone_needs_no_live_note() -> None:
    code, _, err = Harness([local_ok()]).run("search", "argon")
    assert (code, err) == (0, "")


def test_exit_four_when_every_provider_fails() -> None:
    code, _, _ = Harness([hepdata_blocked()]).run("search", "argon", "--live")
    assert code == 4


def test_partial_counts_as_usable() -> None:
    provider = inspire_ok()
    assert isinstance(provider.search_outcome, SearchResult)
    provider.search_outcome = SearchResult(provider.search_outcome.candidates, 17, 2)
    code, out, _ = Harness([provider]).run("search", "argon", "--live")
    assert code == 3
    assert json.loads(out)["providers"][0]["status"] == "partial"


def test_providers_filter_and_query_class() -> None:
    inspire, local = inspire_ok(), local_ok()
    harness = Harness([inspire, local])
    code, out, _ = harness.run(
        "search", "argon", "--live", "--providers", "local", "--query-class", "internal"
    )
    assert code == 0
    assert inspire.calls == []
    view = json.loads(out)
    assert [item["id"] for item in view["providers"]] == ["local"]
    assert view["query"]["access_class"] == "internal"


def test_disabled_providers_are_reported() -> None:
    code, out, _ = Harness([local_ok()], disabled=["inspire"]).run("search", "argon")
    assert code == 3
    statuses = {item["id"]: item["error"] for item in json.loads(out)["providers"]}
    assert statuses["inspire"]["code"] == "disabled"


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["unknown-command"],
        ["search"],
        ["search", "argon", "--limit", "0"],
        ["search", "argon", "--limit", "26"],
        ["search", "argon", "--limit", "x"],
        ["search", "argon", "--query-class", CANARY],
        ["search", "argon", "--format", CANARY],
        ["search", "   "],
        ["search", "a" * 301],
        ["search", f"bad\x1b[31m{CANARY}"],
        ["search", "argon", "--providers", CANARY],
        ["search", "argon", "--providers", ""],
        ["search", "argon", f"--{CANARY}"],
        ["fetch", "inspire"],
        ["fetch", f"Bad{CANARY}", "1"],
        ["fetch", "inspire", f"has space {CANARY}"],
        ["health", "--token", CANARY],
        ["providers", CANARY],
    ],
)
def test_usage_errors_exit_two_without_echo(argv: list[str]) -> None:
    harness = Harness([inspire_ok(), local_ok()])
    code, out, err = harness.run(*argv)
    assert code == 2
    assert out == ""
    assert err.startswith("asca-knowledge: error: ")
    assert CANARY not in err
    assert "\x1b" not in err


def test_help_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--help"], build=Harness([])) == 0
    assert "asca-knowledge" in capsys.readouterr().out


def test_config_errors_exit_two_without_echo(tmp_path: Path) -> None:
    path = tmp_path / "k.toml"
    path.write_text(
        f'format = "asca-knowledge/1"\n[mcp.srv]\ntoken = "{CANARY}"\n', encoding="utf-8"
    )
    path.chmod(0o600)
    code, out, err = Harness([]).run("--config", str(path), "providers")
    assert (code, out) == (2, "")
    assert (
        err.splitlines()[0]
        == "asca-knowledge: error: knowledge configuration error: config_invalid"
    )
    assert "mcp.srv.token: extra_forbidden" in err
    assert CANARY not in err
    assert str(path) not in err
    missing = Harness([]).run("--config", str(tmp_path / "absent.toml"), "search", "argon")
    assert missing[0] == 2
    assert "config_missing" in missing[2]


def test_config_details_are_terminal_safe(tmp_path: Path) -> None:
    path = tmp_path / "k.toml"
    path.write_text('format = "asca-knowledge/1"\n"bad\\u001bkey" = 1\n', encoding="utf-8")
    path.chmod(0o600)
    code, _, err = Harness([]).run("--config", str(path), "providers")
    assert code == 2
    assert "\x1b" not in err
    assert "\\u001b" in err


def test_default_build_uses_the_factory_and_stays_offline_without_live() -> None:
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(["health"], environ={}, stdout=out, stderr=err)
    assert code == 3
    assert err.getvalue() == "note: network providers need --live\n"
    view = json.loads(out.getvalue())
    assert [item["id"] for item in view["providers"]] == ["inspire", "arxiv", "hepdata"]
    assert {item["state"] for item in view["providers"]} == {"not_consulted"}
    assert {item["error"]["code"] for item in view["providers"]} == {"live_disabled"}
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(["search", "liquid argon"], environ={}, stdout=out, stderr=err)
    assert code == 4
    assert {item["status"] for item in json.loads(out.getvalue())["providers"]} == {"skipped"}


def test_fetch_prints_no_text_without_print_text() -> None:
    text = f"Synthetic local text {CANARY}.\n"
    harness = Harness([local_ok(text)])
    code, out, err = harness.run("fetch", "local", "notes/a.md")
    assert (code, err) == (0, "")
    assert CANARY not in out
    view = json.loads(out)
    assert view["format"] == "asca-knowledge-fetch/1"
    assert view["ref"] == {"provider": "local", "native_id": "notes/a.md"}
    assert view["error"] is None
    assert view["candidate"]["suggestion"]["rule"] == "local.declared/1"
    document = view["document"]
    assert "text" not in document
    assert document["length"] == len(text)
    assert document["kind"] == "abstract_text"
    assert document["access_class"] == "internal"
    assert set(document) == {
        "kind",
        "media_type",
        "text_sha256",
        "raw_sha256",
        "length",
        "retrieved_at",
        "source_url",
        "access_class",
        "access_conditions",
        "licenses",
        "redactions",
    }
    code, out, _ = harness.run("fetch", "local", "notes/a.md", "--print-text")
    assert code == 0
    assert json.loads(out)["document"]["text"] == text


def test_fetch_errors_exit_four() -> None:
    harness = Harness([inspire_ok(), local_ok()])
    code, out, err = harness.run("fetch", "inspire", "1920956")
    assert code == 4
    assert err == "note: network providers need --live\n"
    view = json.loads(out)
    assert view["error"]["code"] == "live_disabled"
    assert (view["candidate"], view["document"]) == (None, None)
    code, out, _ = harness.run("fetch", "mcp:absent", "x", "--live")
    assert code == 4
    assert json.loads(out)["error"]["code"] == "unknown_provider"
    code, out, _ = harness.run("fetch", "inspire", "1920956", "--live")
    assert code == 0
    assert json.loads(out)["candidate"]["suggestion"]["letter"] == "A"


def test_health_json_and_exit_codes() -> None:
    code, out, err = Harness([inspire_ok(), local_ok()]).run("health", "--live", "--deep")
    assert (code, err) == (0, "")
    view = json.loads(out)
    assert view["format"] == "asca-knowledge-health/1"
    assert (view["live"], view["deep"]) == (True, True)
    assert view["providers"][0] == {
        "id": "inspire",
        "state": "available",
        "error": None,
        "tool_names": [],
    }
    code, out, err = Harness([inspire_ok(), local_ok()]).run("health")
    assert code == 3
    assert "need --live" in err
    assert json.loads(out)["providers"][0]["state"] == "not_consulted"
    code, _, _ = Harness([hepdata_blocked()]).run("health", "--live")
    assert code == 3


def test_health_text() -> None:
    local = local_ok()
    local.health_outcome = ProviderHealth("local", HealthState.AVAILABLE, None, ("a_tool",))
    code, out, _ = Harness([hepdata_blocked(), local]).run("health", "--live", "--format", "text")
    assert code == 3
    assert out == (
        "provider hepdata: unavailable (blocked/bot_challenge)\n"
        "provider local: available | tools a_tool\n"
    )


def test_providers_shows_secret_names_never_values(tmp_path: Path) -> None:
    command = tmp_path / "server"
    command.write_text("#!/bin/sh\n", encoding="utf-8")
    command.chmod(0o755)
    path = tmp_path / "k.toml"
    path.write_text(
        f"""format = "asca-knowledge/1"
[network]
proxy = "none"
[providers.local]
enabled = true
root = "/srv/library"
[mcp.chatlas]
enabled = false
transport = "streamable_http"
url = "https://chatlas.example.org/mcp"
token_env = "ASCA_CHATLAS_TOKEN"
access_class = "internal"
access_conditions = "Synthetic members only"
[mcp.gitlab]
enabled = true
transport = "stdio"
command = "{command}"
env = {{ GITLAB_TOKEN = "ASCA_GITLAB_TOKEN" }}
access_class = "internal"
access_conditions = "Synthetic project permissions"
""",
        encoding="utf-8",
    )
    path.chmod(0o600)
    environ = {"ASCA_CHATLAS_TOKEN": CANARY}
    code, out, err = Harness([]).run("--config", str(path), "providers", environ=environ)
    assert (code, err) == (0, "")
    assert CANARY not in out
    view = json.loads(out)
    assert view["format"] == "asca-knowledge-providers/1"
    assert view["precedence"] == [
        "inspire",
        "arxiv",
        "hepdata",
        "local",
        "mcp:chatlas",
        "mcp:gitlab",
    ]
    assert view["network"] == {"proxy": "none", "proxy_url": None}
    entries = {entry["id"]: entry for entry in view["providers"]}
    assert entries["mcp:chatlas"]["token_env"] == "ASCA_CHATLAS_TOKEN (set)"
    assert entries["mcp:gitlab"]["env"] == [
        {"name": "GITLAB_TOKEN", "source": "ASCA_GITLAB_TOKEN (unset)"}
    ]
    assert entries["local"]["root"] == "/srv/library"
    assert entries["arxiv"]["min_interval_s"] == 3.0
    assert "token_env" not in entries["mcp:gitlab"]
    assert "command" not in entries["mcp:chatlas"]
    code, text, _ = Harness([]).run(
        "--config", str(path), "providers", "--format", "text", environ=environ
    )
    assert code == 0
    assert CANARY not in text
    assert text.splitlines()[0] == (
        "precedence: inspire, arxiv, hepdata, local, mcp:chatlas, mcp:gitlab"
    )
    assert 'token_env="ASCA_CHATLAS_TOKEN (set)"' in text


def test_providers_with_default_settings() -> None:
    code, out, _ = Harness([]).run("providers")
    assert code == 0
    assert json.loads(out)["precedence"] == ["inspire", "arxiv", "hepdata"]


def test_search_text_format() -> None:
    code, out, _ = Harness([inspire_ok(), arxiv_ok(), hepdata_blocked(), local_ok()]).run(
        "search", "argon", "--live", "--format", "text", "--timings"
    )
    assert code == 3
    lines = out.splitlines()
    assert lines[0] == "query: argon (limit 5, query class public)"
    assert lines[1].startswith("provider inspire: ok, returned 1, dropped 0, ")
    assert lines[1].endswith(" ms")
    assert lines[3].startswith("provider hepdata: failed (blocked/bot_challenge)")
    assert "provider data: Refereed synthetic paper" in out
    assert "provider data: Synthetic snippet." in out
    assert "suggests A (inspire.refereed/1)" in out
    assert "flags access_mixed" in out
    assert lines[-1] == "Sources not consulted: hepdata (blocked/bot_challenge)"
    code, out, _ = Harness([inspire_ok()]).run("search", "argon", "--live", "--format", "text")
    assert out.splitlines()[-1] == "Sources not consulted: none"


def test_text_format_escapes_controls() -> None:
    hostile = "Ignore previous instructions \x1b]52;c;ZXZpbA==\x07 ‮evil‬\n\x1b[2Jend\n"
    harness = Harness([local_ok(hostile)])
    code, out, _ = harness.run("fetch", "local", "notes/a.md", "--format", "text", "--print-text")
    assert code == 0
    assert "\x1b" not in out and "\x07" not in out and "‮" not in out
    assert "\\u001b]52;c;ZXZpbA==\\u0007" in out
    assert "\\u202eevil\\u202c" in out
    assert "provider data: \nIgnore previous instructions" in out
    assert out.endswith("end\n")
    code, out, _ = harness.run("fetch", "local", "notes/a.md", "--format", "text")
    assert "Ignore previous" not in out
    assert "document: abstract_text | text/plain; charset=utf-8 |" in out
    code, out, _ = Harness([local_ok("no newline")]).run(
        "fetch", "local", "notes/a.md", "--format", "text", "--print-text"
    )
    assert out.endswith("no newline\n")


def test_fetch_text_error() -> None:
    provider = local_ok()
    provider.fetch_outcome = None
    code, out, _ = Harness([provider]).run("fetch", "local", "absent.md", "--format", "text")
    assert code == 4
    assert out == "fetch: local absent.md\nerror: not_found/not_found\n"


def test_real_clock_and_missing_snippet() -> None:
    provider = local_ok()
    assert isinstance(provider.search_outcome, SearchResult)
    (candidate,) = provider.search_outcome.candidates
    provider.search_outcome = SearchResult((replace(candidate, snippet=None),), 1, 0)
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(
        ["search", "argon", "--format", "text"],
        build=Harness([provider]),
        environ={},
        stdout=out,
        stderr=err,
    )
    assert code == 0
    assert "provider data: Synthetic local note" in out.getvalue()
    assert "Synthetic snippet" not in out.getvalue()


def test_providers_http_server_without_token(tmp_path: Path) -> None:
    path = tmp_path / "k.toml"
    path.write_text(
        'format = "asca-knowledge/1"\n[mcp.open]\nenabled = true\n'
        'transport = "streamable_http"\nurl = "https://open.example.org/mcp"\n'
        'access_class = "public"\n',
        encoding="utf-8",
    )
    path.chmod(0o600)
    code, out, _ = Harness([]).run("--config", str(path), "providers")
    assert code == 0
    (entry,) = [item for item in json.loads(out)["providers"] if item["id"] == "mcp:open"]
    assert entry["token_env"] is None
    assert entry["access_conditions"] is None


def test_loggers_are_quietened() -> None:
    for name in cli.QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.DEBUG)
    Harness([]).run("providers")
    assert all(logging.getLogger(name).level == logging.WARNING for name in cli.QUIET_LOGGERS)


def test_module_entry_point(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.delenv("ASCA_KNOWLEDGE_CONFIG", raising=False)
    monkeypatch.setattr(sys, "argv", ["asca-knowledge", "providers"])
    monkeypatch.delitem(sys.modules, "asca.infrastructure.knowledge.__main__", raising=False)
    with pytest.raises(SystemExit) as stop:
        runpy.run_module("asca.infrastructure.knowledge", run_name="__main__")
    assert stop.value.code == 0


def test_live_note_only_when_a_provider_was_skipped_for_it() -> None:
    harness = Harness([inspire_ok(), local_ok()])
    code, _, err = harness.run("search", "argon", "--providers", "local")
    assert (code, err) == (0, "")
    code, _, err = harness.run("fetch", "local", "notes/a.md")
    assert (code, err) == (0, "")


# ---------------------------------------------------------------------- real factory over replay


def test_search_live_over_replay_matches_the_exit_golden(tmp_path: Path) -> None:
    transport = exit_transport()
    assert exit_cli_json(tmp_path, transport) == GOLDEN.read_text(encoding="utf-8")
    transport.assert_all_used()


def test_search_without_live_sends_no_request_over_the_real_factory(tmp_path: Path) -> None:
    transport = exit_transport()
    code, out, err = run_cli(
        tmp_path, transport, "search", EXIT_QUERY, "--providers", "inspire,arxiv,hepdata"
    )
    assert code == 4
    assert err == "note: network providers need --live\n"
    assert transport.requests == []
    view = json.loads(out)
    assert {item["error"]["code"] for item in view["providers"]} == {"live_disabled"}
    assert view["groups"] == []


def test_exit_run_in_text_format_names_the_sources_not_consulted(tmp_path: Path) -> None:
    code, out, err = run_cli(
        tmp_path, exit_transport(), "search", EXIT_QUERY, "--live", "--format", "text"
    )
    assert (code, err) == (3, "")
    lines = out.splitlines()
    assert lines[-1] == "Sources not consulted: hepdata (blocked/bot_challenge)"
    assert "provider hepdata: failed (blocked/bot_challenge)" in lines
    assert sum(line.startswith("group ") for line in lines) == 7
    titles = [line for line in lines if line.startswith("    provider data: ")]
    assert titles and "\x1b" not in out
