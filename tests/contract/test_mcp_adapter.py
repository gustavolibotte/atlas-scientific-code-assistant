"""Contract tests for the generic MCP adapter (in-process, stdio and loopback HTTP).

No test leaves the machine: the in-process server runs through the ``connector`` seam,
stdio runs the synthetic server through the guard, and HTTP uses 127.0.0.1.
"""

import asyncio
import os
import socket
import time
from pathlib import Path

import anyio
import httpx2
import mcp
import mcp_types
import pydantic
import pytest
from fake_mcp_server import FakeState, tool_definitions
from knowledge_contract import assert_provider_contract
from mcp_http_server import LoopbackMcpServer
from mcp_testing import (
    INTERNAL_QUERY,
    NO_PROXY,
    TOKEN,
    TOKEN_ENV,
    FixedClock,
    http_provider,
    in_process_provider,
    make_settings,
    stdio_provider,
)

from asca.application.knowledge.models import (
    CandidateRef,
    ContentAvailability,
    DocumentKind,
    FetchResult,
    HealthState,
    KnowledgeQuery,
    PidOrigin,
    PidRole,
    ProviderError,
    ProviderErrorKind,
    ProviderKind,
    SearchResult,
    VersionKind,
)
from asca.application.knowledge.policy import suggest_authority
from asca.domain.provenance import AccessClass, PidScheme, SourceAuthority
from asca.infrastructure.knowledge import mcp_client
from asca.infrastructure.knowledge.mcp_client import McpKnowledgeProvider, tools_fingerprint
from asca.infrastructure.knowledge.settings import McpResultKind

pytestmark = pytest.mark.contract

REF = CandidateRef("mcp:test", "doc-1")


def _search(provider: McpKnowledgeProvider, query: KnowledgeQuery = INTERNAL_QUERY) -> object:
    return asyncio.run(provider.search(query))


def _fetch(provider: McpKnowledgeProvider, ref: CandidateRef = REF) -> object:
    return asyncio.run(provider.fetch(ref))


def _error(outcome: object) -> tuple[ProviderErrorKind, str]:
    assert isinstance(outcome, ProviderError), outcome
    return outcome.kind, outcome.code


def _pin(mode: str = "normal") -> str:
    tools = [tool for tool in tool_definitions(mode) if tool["name"] in ("search", "fetch")]
    return tools_fingerprint(tools)


# ---------------------------------------------------------------------- descriptor


def test_descriptor_comes_from_settings() -> None:
    descriptor = in_process_provider().descriptor
    assert descriptor.id == "mcp:test"
    assert descriptor.kind is ProviderKind.MCP
    assert descriptor.label == "MCP test"
    assert descriptor.adapter_version == "mcp/1"
    assert descriptor.access_class is AccessClass.INTERNAL
    assert descriptor.max_query_access is AccessClass.INTERNAL
    assert descriptor.uses_network is True
    assert descriptor.supports_fetch is True
    no_fetch = in_process_provider(settings=make_settings(fetch_tool=None))
    assert no_fetch.descriptor.supports_fetch is False


def test_provider_contract_helper_passes() -> None:
    assert_provider_contract(in_process_provider(), INTERNAL_QUERY)


# ---------------------------------------------------------------------- search and fetch


def test_search_maps_items_with_access_from_settings_and_related_pids_only() -> None:
    state = FakeState()
    outcome = _search(in_process_provider(state=state))
    assert isinstance(outcome, SearchResult)
    assert [item.ref.native_id for item in outcome.candidates] == ["doc-1", "doc-2"]
    assert outcome.dropped_items == 2
    assert outcome.total_reported == 4
    first = outcome.candidates[0]
    assert first.access_class is AccessClass.INTERNAL
    assert first.access_conditions == "Synthetic internal test material."
    assert first.identity_pids == ()
    assert all(
        pid.role is PidRole.RELATED and pid.origin is PidOrigin.PROVIDER_ASSERTED
        for pid in first.pids
    )
    schemes = [pid.pid.scheme for pid in first.pids]
    assert schemes == [
        PidScheme.DOI,
        PidScheme.ARXIV,
        PidScheme.INSPIRE,
        PidScheme.CDS_REPORT,
        PidScheme.URL,
    ]
    assert first.landing_url == "https://docs.example.org/notes/doc-1"
    assert first.version.kind is VersionKind.DECLARED
    assert first.version.label == "declared:2"
    assert first.issued is not None and first.issued.iso() == "2021-09"
    assert first.content is ContentAvailability.FULL_TEXT
    assert first.declared_authority is SourceAuthority.WORKING_MATERIAL
    assert first.snippet == "Synthetic snippet about energy reconstruction."
    second = outcome.candidates[1]
    assert second.version.label == "retrieved@2026-11-14"
    assert second.pids == ()
    assert suggest_authority(first).authority is SourceAuthority.WORKING_MATERIAL
    assert state.tool_calls == [("search", {"query": "calorimeter energy", "limit": 5})]


def test_search_respects_the_query_limit() -> None:
    outcome = _search(in_process_provider(), KnowledgeQuery("x", 1, AccessClass.INTERNAL))
    assert isinstance(outcome, SearchResult)
    assert len(outcome.candidates) == 1


def test_search_without_limit_argument_sends_only_the_query() -> None:
    state = FakeState()
    provider = in_process_provider(state=state, settings=make_settings(search_limit_arg=None))
    assert isinstance(_search(provider), SearchResult)
    assert state.tool_calls == [("search", {"query": "calorimeter energy"})]


def test_fetch_returns_tool_text_document() -> None:
    state = FakeState()
    outcome = _fetch(in_process_provider(state=state))
    assert isinstance(outcome, FetchResult)
    document = outcome.document
    assert document.kind is DocumentKind.TOOL_TEXT
    assert document.text == "Synthetic full text.\nSecond line."
    assert document.media_type == "text/plain; charset=utf-8"
    assert document.raw_sha256 is None
    assert document.source_url is None
    assert document.redactions == 0
    assert document.access_class is AccessClass.INTERNAL
    assert outcome.candidate.ref == REF
    assert state.tool_calls == [("fetch", {"id": "doc-1"})]


def test_generated_results_suggest_automated_inference_and_generated_text() -> None:
    provider = in_process_provider(settings=make_settings(result_kind=McpResultKind.GENERATED))
    outcome = _search(provider)
    assert isinstance(outcome, SearchResult)
    candidate = outcome.candidates[0]
    assert candidate.facts.generated is True
    assert candidate.declared_authority is SourceAuthority.AUTOMATED_INFERENCE
    assert suggest_authority(candidate).authority is SourceAuthority.AUTOMATED_INFERENCE
    fetched = _fetch(provider)
    assert isinstance(fetched, FetchResult)
    assert fetched.document.kind is DocumentKind.GENERATED_TEXT


def test_metadata_only_without_fetch_tool() -> None:
    provider = in_process_provider(settings=make_settings(fetch_tool=None))
    outcome = _search(provider)
    assert isinstance(outcome, SearchResult)
    assert outcome.candidates[0].content is ContentAvailability.METADATA_ONLY
    assert _error(_fetch(provider)) == (ProviderErrorKind.UNSUPPORTED, "fetch_unsupported")


def test_single_json_text_block_is_parsed() -> None:
    outcome = _search(in_process_provider("text_json"))
    assert isinstance(outcome, SearchResult)
    assert [item.ref.native_id for item in outcome.candidates] == ["doc-1", "doc-2"]


def test_non_json_text_is_an_unexpected_payload() -> None:
    assert _error(_search(in_process_provider("text_plain"))) == (
        ProviderErrorKind.MALFORMED_RESPONSE,
        "unexpected_payload",
    )


def test_tool_error_is_not_echoed() -> None:
    outcome = _search(in_process_provider("error"))
    assert _error(outcome) == (ProviderErrorKind.TOOL_ERROR, "tool_error")
    assert "canary" not in repr(outcome)


def test_fetch_with_another_id_is_an_unexpected_payload() -> None:
    assert _error(_fetch(in_process_provider("fetch_mismatch"))) == (
        ProviderErrorKind.MALFORMED_RESPONSE,
        "unexpected_payload",
    )


@pytest.mark.parametrize(
    "ref",
    [
        CandidateRef("inspire", "doc-1"),
        CandidateRef("mcp:other", "doc-1"),
        CandidateRef("mcp:test", "é"),
    ],
)
def test_fetch_refuses_foreign_or_invalid_refs_without_a_session(ref: CandidateRef) -> None:
    state = FakeState()
    outcome = _fetch(in_process_provider(state=state), ref)
    assert _error(outcome) == (ProviderErrorKind.UNSUPPORTED, "invalid_native_id")
    assert state.list_calls == 0


def test_query_above_max_query_access_is_refused_without_a_session() -> None:
    state = FakeState()
    query = KnowledgeQuery("x", 5, AccessClass.RESTRICTED)
    outcome = _search(in_process_provider(state=state), query)
    assert _error(outcome) == (ProviderErrorKind.NOT_CONSULTED, "query_access_class")
    assert state.list_calls == 0


# ---------------------------------------------------------------------- discovery


def test_missing_tool_is_not_configured() -> None:
    provider = in_process_provider(settings=make_settings(search_tool="find"))
    assert _error(_search(provider)) == (ProviderErrorKind.NOT_CONFIGURED, "tool_missing")


def test_missing_fetch_tool_is_not_configured() -> None:
    provider = in_process_provider(settings=make_settings(fetch_tool="get"))
    assert _error(_search(provider)) == (ProviderErrorKind.NOT_CONFIGURED, "tool_missing")


@pytest.mark.parametrize(
    ("mode", "overrides"),
    [
        ("schema_int", {}),
        ("normal", {"search_query_arg": "q"}),
        ("normal", {"search_limit_arg": "query"}),
        ("normal", {"fetch_id_arg": "query"}),
        ("normal", {"search_tool": "delete_all", "search_limit_arg": None, "fetch_tool": None}),
    ],
)
def test_tool_contract_mismatch_is_not_configured(mode: str, overrides: dict[str, object]) -> None:
    state = FakeState()
    provider = in_process_provider(mode, state=state, settings=make_settings(**overrides))
    assert _error(_search(provider)) == (
        ProviderErrorKind.NOT_CONFIGURED,
        "tool_contract_mismatch",
    )
    assert state.tool_calls == []


def test_more_than_200_tools_is_a_protocol_error() -> None:
    state = FakeState()
    outcome = _search(in_process_provider("many_tools", state=state))
    assert _error(outcome) == (ProviderErrorKind.PROTOCOL_ERROR, "too_many_tools")
    assert state.list_calls == 3
    assert state.tool_calls == []


def test_matching_pin_allows_the_call() -> None:
    provider = in_process_provider(settings=make_settings(expected_tools_sha256=_pin()))
    assert isinstance(_search(provider), SearchResult)


def test_pin_mismatch_makes_no_call() -> None:
    state = FakeState()
    provider = in_process_provider(
        "schema_v2", state=state, settings=make_settings(expected_tools_sha256=_pin())
    )
    assert _error(_search(provider)) == (ProviderErrorKind.PROTOCOL_ERROR, "tool_schema_changed")
    assert state.tool_calls == []


def test_tools_fingerprint_is_order_independent() -> None:
    tools = [tool for tool in tool_definitions("normal") if tool["name"] in ("search", "fetch")]
    assert tools_fingerprint(tools) == tools_fingerprint(list(reversed(tools)))
    assert tools_fingerprint(tools) != _pin("schema_v2")


def test_health_lists_tool_names_only() -> None:
    health = asyncio.run(in_process_provider().health(deep=True))
    assert health.state is HealthState.AVAILABLE
    assert health.error is None
    assert health.tool_names == ("delete_all", "fetch", "search")
    assert "Deletes everything" not in repr(health)


def test_health_maps_configuration_and_protocol_failures() -> None:
    missing = in_process_provider(settings=make_settings(search_tool="find"))
    health = asyncio.run(missing.health())
    assert health.state is HealthState.MISCONFIGURED
    assert health.error is not None and health.error.code == "tool_missing"
    many = asyncio.run(in_process_provider("many_tools").health())
    assert many.state is HealthState.UNAVAILABLE
    assert many.error is not None and many.error.code == "too_many_tools"


# ---------------------------------------------------------------------- stdio (2 launches)


def test_stdio_round_trip_through_the_guard() -> None:
    outcome = _search(stdio_provider("normal"))
    assert isinstance(outcome, SearchResult)
    assert [item.ref.native_id for item in outcome.candidates] == ["doc-1", "doc-2"]


def test_hung_stdio_server_times_out_and_leaves_no_process(tmp_path: Path) -> None:
    pid_file = tmp_path / "server.pid"
    provider = stdio_provider("hang", pid_file=pid_file, timeout_s=1.0)
    started = time.monotonic()
    outcome = _search(provider)
    elapsed = time.monotonic() - started
    assert _error(outcome) == (ProviderErrorKind.TIMEOUT, "provider_timeout")
    assert elapsed < 1.0 + 3.0
    pid = int(pid_file.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_unsafe_stdio_commands_are_refused(tmp_path: Path) -> None:
    writable = tmp_path / "server"
    writable.write_text("#!/bin/sh\n", encoding="utf-8")
    writable.chmod(0o777)
    not_executable = tmp_path / "plain"
    not_executable.write_text("", encoding="utf-8")
    not_executable.chmod(0o644)
    for command in (str(writable), str(not_executable), str(tmp_path / "missing"), str(tmp_path)):
        provider = stdio_provider("normal", command=command)
        assert _error(_search(provider)) == (ProviderErrorKind.NOT_CONFIGURED, "unsafe_command")


# ---------------------------------------------------------------------- loopback HTTP


def test_loopback_http_with_a_good_token() -> None:
    with LoopbackMcpServer(token=TOKEN) as server:
        provider = http_provider(server.url)
        outcome = _search(provider)
        fetched = _fetch(provider)
        health = asyncio.run(provider.health())
    assert isinstance(outcome, SearchResult)
    assert [item.ref.native_id for item in outcome.candidates] == ["doc-1", "doc-2"]
    assert isinstance(fetched, FetchResult)
    assert health.state is HealthState.AVAILABLE
    assert server.requests and all(request.authorized for request in server.requests)
    assert ("search", {"query": "calorimeter energy", "limit": 5}) in server.state.tool_calls


def test_loopback_http_with_a_bad_token_requires_auth() -> None:
    with LoopbackMcpServer(token=TOKEN) as server:
        provider = http_provider(server.url, environ={TOKEN_ENV: "wrong-token-0123456789"})
        outcome = _search(provider)
        health = asyncio.run(provider.health())
    assert outcome == ProviderError(ProviderErrorKind.AUTH_REQUIRED, "http_401", 401)
    assert health.state is HealthState.AUTH_REQUIRED
    assert server.state.tool_calls == []


def test_loopback_http_reports_an_oauth_resource_metadata_challenge() -> None:
    with LoopbackMcpServer(token=TOKEN, advertise_resource_metadata=True) as server:
        provider = http_provider(server.url, environ={TOKEN_ENV: "wrong-token-0123456789"})
        outcome = _search(provider)
    assert _error(outcome) == (ProviderErrorKind.AUTH_REQUIRED, "oauth_resource_metadata")


def test_unset_token_variable_makes_no_connection() -> None:
    with LoopbackMcpServer(token=TOKEN) as server:
        outcome = _search(http_provider(server.url, environ={}))
        health = asyncio.run(http_provider(server.url, environ={}).health())
    assert _error(outcome) == (ProviderErrorKind.NOT_CONFIGURED, "token_missing")
    assert health.state is HealthState.MISCONFIGURED
    assert server.requests == []


def test_malformed_token_is_refused_before_connecting() -> None:
    with LoopbackMcpServer(token=TOKEN) as server:
        outcome = _search(http_provider(server.url, environ={TOKEN_ENV: "short"}))
    assert _error(outcome) == (ProviderErrorKind.NOT_CONFIGURED, "token_invalid")
    assert server.requests == []


def test_http_server_without_token_variable_sends_no_authorization() -> None:
    with LoopbackMcpServer(token=TOKEN) as server:
        outcome = _search(http_provider(server.url, token_env=None, environ={}))
    assert _error(outcome)[0] is ProviderErrorKind.AUTH_REQUIRED
    assert server.requests and not any(request.had_authorization for request in server.requests)


def test_http_connection_refused_is_a_connect_failure() -> None:
    with LoopbackMcpServer(token=TOKEN) as server:
        url = server.url
    outcome = _search(http_provider(url))
    assert _error(outcome) == (ProviderErrorKind.CONNECT_FAILED, "connect_failed")


# ---------------------------------------------------------------------- payload shapes


def _structured(payload: object) -> mcp_types.CallToolResult:
    return mcp_types.CallToolResult(content=[], structured_content=payload)


def _texts(*texts: str) -> mcp_types.CallToolResult:
    return mcp_types.CallToolResult(content=[mcp_types.TextContent(text=text) for text in texts])


def _nested(depth: int) -> dict[str, object]:
    value: dict[str, object] = {"leaf": "x"}
    for _ in range(depth):
        value = {"child": value}
    return value


@pytest.mark.parametrize(
    "result",
    [
        _structured({"results": "not a list"}),
        _structured({"results": [], "deep": _nested(70)}),
        _texts('{"results": []}', '{"results": []}'),
        _texts("[1, 2]"),
        _texts('{"results": [], "pad": "' + "x" * 1_048_576 + '"}'),
        mcp_types.CallToolResult(content=[]),
    ],
)
def test_malformed_search_payloads_are_refused(result: mcp_types.CallToolResult) -> None:
    provider = in_process_provider(respond=lambda name, arguments: result)
    assert _error(_search(provider)) == (
        ProviderErrorKind.MALFORMED_RESPONSE,
        "unexpected_payload",
    )


def test_invalid_search_items_are_dropped() -> None:
    items: list[object] = [
        "not an object",
        {"id": "a", "title": "   "},
        {"id": "a", "title": 3},
        {"id": "x" * 201, "title": "Too long an id"},
        {"id": "kept", "title": "Kept", "url": "http://insecure.example/x", "metadata": []},
        {"id": "blank-version", "title": "Blank version", "metadata": {"version": " \x00 "}},
        {"id": "bool-recid", "title": "Bool recid", "metadata": {"recid": True, "doi": "x"}},
    ]
    provider = in_process_provider(respond=lambda name, arguments: _structured({"results": items}))
    outcome = _search(provider, KnowledgeQuery("x", 25, AccessClass.INTERNAL))
    assert isinstance(outcome, SearchResult)
    assert [item.ref.native_id for item in outcome.candidates] == [
        "kept",
        "blank-version",
        "bool-recid",
    ]
    assert outcome.dropped_items == 4
    kept = outcome.candidates[0]
    assert kept.landing_url is None
    assert kept.pids == ()
    assert outcome.candidates[1].version.kind is VersionKind.RECORD_SNAPSHOT
    assert outcome.candidates[2].pids == ()


@pytest.mark.parametrize(
    "payload",
    [
        {"id": "doc-1", "title": "No text"},
        {"id": "doc-1", "title": "Blank text", "text": " \x00\x01 "},
        {"id": "doc-1", "text": "No title."},
        {"id": "doc-1", "title": "Too big", "text": "x" * (4 * 1024 * 1024 + 1)},
    ],
)
def test_malformed_fetch_payloads_are_refused(payload: dict[str, object]) -> None:
    provider = in_process_provider(respond=lambda name, arguments: _structured(payload))
    assert _error(_fetch(provider)) == (
        ProviderErrorKind.MALFORMED_RESPONSE,
        "unexpected_payload",
    )


def test_a_tool_schema_without_properties_is_a_contract_mismatch() -> None:
    tools = [
        {"name": "search", "description": None, "input_schema": {"type": "object"}},
        {
            "name": "fetch",
            "description": None,
            "input_schema": {"type": "object", "properties": []},
        },
    ]
    provider = in_process_provider(tools=tools)
    assert _error(_search(provider)) == (
        ProviderErrorKind.NOT_CONFIGURED,
        "tool_contract_mismatch",
    )


def test_more_than_five_tool_pages_is_a_protocol_error() -> None:
    six = tool_definitions("normal") + [
        {"name": f"extra-{index}", "description": None, "input_schema": {"type": "object"}}
        for index in range(3)
    ]
    state = FakeState()
    provider = in_process_provider(state=state, tools=six, page_size=1)
    assert _error(_search(provider)) == (ProviderErrorKind.PROTOCOL_ERROR, "too_many_tools")
    assert state.list_calls == 5
    assert state.tool_calls == []
    two_pages = in_process_provider(page_size=2)
    assert isinstance(_search(two_pages), SearchResult)


def test_loopback_http_refused_without_the_loopback_flag() -> None:
    provider = http_provider("https://127.0.0.1:9/mcp", allow_insecure_loopback=False)
    assert _error(_search(provider)) == (ProviderErrorKind.NOT_CONFIGURED, "unsafe_url")


# ---------------------------------------------------------------------- error mapping


def test_a_cancellation_group_after_the_deadline_is_a_timeout() -> None:
    async def hang_then_group(name: str, arguments: dict[str, object]) -> object:
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError as cancelled:
            raise BaseExceptionGroup("cancelled", [cancelled]) from None
        return None  # pragma: no cover

    class Hanging:
        async def __aenter__(self) -> "Hanging":
            return self

        async def __aexit__(self, *exc: object) -> None:
            return None

        async def list_tools(self, cursor: str | None = None) -> object:
            await hang_then_group("list", {})
            return None  # pragma: no cover

    provider = McpKnowledgeProvider(
        make_settings(timeout_s=1.0),
        network=NO_PROXY,
        clock=FixedClock(),
        connector=lambda: Hanging(),  # type: ignore[arg-type,return-value]
    )
    assert _error(_search(provider)) == (ProviderErrorKind.TIMEOUT, "provider_timeout")


def test_other_base_exception_groups_propagate() -> None:
    class Interrupting:
        async def __aenter__(self) -> "Interrupting":
            raise BaseExceptionGroup("stop", [KeyboardInterrupt()])

        async def __aexit__(self, *exc: object) -> None:
            return None  # pragma: no cover

    provider = McpKnowledgeProvider(
        make_settings(),
        network=NO_PROXY,
        clock=FixedClock(),
        connector=lambda: Interrupting(),  # type: ignore[arg-type,return-value]
    )
    with pytest.raises(BaseExceptionGroup):
        _search(provider)


def _mapped(provider: McpKnowledgeProvider, exc: BaseException) -> tuple[ProviderErrorKind, str]:
    error = provider._map_exception(exc, mcp_client._Observed())
    return error.kind, error.code


def test_exception_mapping_uses_fixed_codes() -> None:
    stdio = stdio_provider("normal")
    http = http_provider("http://127.0.0.1:9/mcp")
    validation = None
    try:
        mcp_types.Implementation.model_validate({})
    except pydantic.ValidationError as exc:
        validation = exc
    assert validation is not None
    cases: list[tuple[McpKnowledgeProvider, BaseException, tuple[ProviderErrorKind, str]]] = [
        (stdio, TimeoutError(), (ProviderErrorKind.TIMEOUT, "provider_timeout")),
        (
            stdio,
            mcp.MCPError(mcp_types.REQUEST_TIMEOUT, "secret-canary"),
            (ProviderErrorKind.TIMEOUT, "provider_timeout"),
        ),
        (
            stdio,
            mcp.MCPError(mcp_types.CONNECTION_CLOSED, "closed"),
            (ProviderErrorKind.PROCESS_FAILED, "process_exited"),
        ),
        (
            http,
            mcp.MCPError(mcp_types.CONNECTION_CLOSED, "closed"),
            (ProviderErrorKind.PROTOCOL_ERROR, "mcp_error"),
        ),
        (stdio, FileNotFoundError(), (ProviderErrorKind.PROCESS_FAILED, "spawn_failed")),
        (http, ConnectionRefusedError(), (ProviderErrorKind.CONNECT_FAILED, "connect_failed")),
        (http, socket.gaierror(), (ProviderErrorKind.DNS_FAILED, "dns_failed")),
        (
            stdio,
            anyio.ClosedResourceError(),
            (ProviderErrorKind.PROCESS_FAILED, "process_exited"),
        ),
        (http, anyio.EndOfStream(), (ProviderErrorKind.PROTOCOL_ERROR, "mcp_error")),
        (http, httpx2.ReadTimeout("t"), (ProviderErrorKind.TIMEOUT, "provider_timeout")),
        (
            http,
            httpx2.RemoteProtocolError("bad"),
            (ProviderErrorKind.MALFORMED_RESPONSE, "unexpected_payload"),
        ),
        (http, validation, (ProviderErrorKind.MALFORMED_RESPONSE, "unexpected_payload")),
        (
            http,
            RuntimeError("secret-canary"),
            (ProviderErrorKind.INTERNAL_ERROR, "unexpected_exception"),
        ),
        (
            stdio,
            ExceptionGroup("g", [RuntimeError("x"), ExceptionGroup("h", [TimeoutError()])]),
            (ProviderErrorKind.TIMEOUT, "provider_timeout"),
        ),
        (
            stdio,
            ExceptionGroup("g", [mcp.MCPError(mcp_types.CONNECTION_CLOSED, "c"), ValueError()]),
            (ProviderErrorKind.PROCESS_FAILED, "process_exited"),
        ),
        (
            stdio,
            ExceptionGroup(
                "g",
                [
                    TimeoutError(),
                    mcp_client._Refused(
                        ProviderError(ProviderErrorKind.NOT_CONFIGURED, "tool_missing")
                    ),
                ],
            ),
            (ProviderErrorKind.NOT_CONFIGURED, "tool_missing"),
        ),
    ]
    for provider, exc, expected in cases:
        assert _mapped(provider, exc) == expected, exc


def test_observed_auth_statuses_take_precedence() -> None:
    provider = http_provider("http://127.0.0.1:9/mcp")
    forbidden = mcp_client._Observed(statuses=[200, 403])
    error = provider._map_exception(mcp.MCPError(mcp_types.INTERNAL_ERROR, "x"), forbidden)
    assert error == ProviderError(ProviderErrorKind.AUTH_REQUIRED, "http_403", 403)
    assert mcp_client._Observed(statuses=[200]).auth_error() is None
