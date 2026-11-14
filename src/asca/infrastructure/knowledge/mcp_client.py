"""Generic MCP knowledge adapter: streamable HTTP, or stdio through the resource guard.

One session per operation: connect, list tools, at most one call of a configured tool,
close. Only configured tool names are ever called. Results are provider data, never
instructions: nothing in a result causes another call, a fetch or a process launch.
Server instructions and tool descriptions are never stored, printed or returned (a
description only enters the optional schema pin as a hash input).

The bearer token comes from an ``ASCA_`` environment variable, is sent only to the
configured origin (the SDK follows same-origin redirects only), and every echo of it in
a result is replaced with ``[REDACTED]``. Exception text is never used.

MCP-asserted identifiers are RELATED pids only: they never merge candidates (ADR 0040).
"""

import asyncio
import contextlib
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import sys
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final, TextIO, TypeVar
from urllib.parse import urlsplit

import httpx2
import mcp
import mcp_types
from mcp.client.streamable_http import streamable_http_client
from pydantic import ValidationError

import asca
from asca.application.knowledge.models import (
    DOCUMENT_TEXT_MAX_BYTES,
    LANDING_URL_MAX,
    RESULTS_MAX,
    SNIPPET_MAX,
    CandidatePid,
    CandidateRef,
    CandidateVersion,
    ContentAvailability,
    DocumentKind,
    FetchedDocument,
    FetchOutcome,
    FetchResult,
    HealthState,
    KnowledgeCandidate,
    KnowledgeQuery,
    PartialDate,
    PidOrigin,
    PidRole,
    ProviderDescriptor,
    ProviderError,
    ProviderErrorKind,
    ProviderHealth,
    ProviderKind,
    PublicationFacts,
    SearchOutcome,
    SearchResult,
    VersionKind,
    is_https_url,
)
from asca.application.knowledge.pids import (
    normalize_arxiv,
    normalize_doi,
    normalize_inspire,
    normalize_report_number,
    pid_sort_key,
)
from asca.application.knowledge.text import clean_block, clean_line
from asca.application.ports import Clock
from asca.domain.provenance import (
    TITLE_MAX,
    AccessClass,
    PersistentIdentifier,
    PidScheme,
    SourceAuthority,
    most_restrictive,
    sha256_text,
)
from asca.infrastructure.knowledge.http import (
    ClientFactory,
    ClientSpec,
    ResponseTooLarge,
    UnsupportedEncoding,
    default_client_factory,
    map_transport_error,
    select_proxy,
    strict_json,
)
from asca.infrastructure.knowledge.secrets import RedactedSecret, read_secret_env, redact_echoes
from asca.infrastructure.knowledge.settings import (
    McpResultKind,
    McpServerSettings,
    McpTransport,
    NetworkSettings,
)
from asca.infrastructure.knowledge.url_guard import (
    UnsafeUrl,
    check_resolved_addresses,
    validate_endpoint_url,
)

ADAPTER_VERSION: Final = "mcp/1"
TOOLS_MAX: Final = 200
TOOL_PAGES_MAX: Final = 5
TEXT_BLOCK_MAX_BYTES: Final = 1_048_576
RESPONSE_MAX_BYTES: Final = 4 * 1024 * 1024
SSE_EVENT_MAX_BYTES: Final = 1_048_576
PAYLOAD_DEPTH_MAX: Final = 64
VERSION_TEXT_MAX: Final = 90
GUARD_MODULE: Final = "asca.infrastructure.knowledge.mcp_stdio_guard"
GUARD_MAX_LINE: Final = 4_194_304
GUARD_MAX_TOTAL: Final = 16_777_216
GUARD_CPU_S: Final = 60
ACCEPT: Final = "application/json, text/event-stream"
MEDIA_TYPE: Final = "text/plain; charset=utf-8"
STRICTER_CONDITIONS: Final = "Marked as more restricted by the MCP server; no conditions stated."
NATIVE_ID_RE: Final = re.compile(r"[\x21-\x7e]{1,200}")
_TOOL_NAME_RE: Final = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_ANYIO_CLOSED: Final = frozenset({"ClosedResourceError", "BrokenResourceError", "EndOfStream"})

McpConnector = Callable[[], contextlib.AbstractAsyncContextManager[mcp.Client]]
_T = TypeVar("_T")


def _error(kind: ProviderErrorKind, code: str, status: int | None = None) -> ProviderError:
    return ProviderError(kind, code, status)


class _Refused(Exception):  # noqa: N818 - an internal control-flow signal, never raised out
    """Short-circuits an operation with a fixed ``ProviderError``."""

    def __init__(self, error: ProviderError) -> None:
        super().__init__(error.code)
        self.error = error


def _refuse(kind: ProviderErrorKind, code: str) -> _Refused:
    return _Refused(_error(kind, code))


def _unexpected_payload() -> _Refused:
    return _refuse(ProviderErrorKind.MALFORMED_RESPONSE, "unexpected_payload")


async def _drop_log(params: mcp_types.LoggingMessageNotificationParams) -> None:
    """Server log messages are dropped."""


def _devnull() -> TextIO:
    """The server's stderr sink: nothing a server writes there reaches the user."""
    return open(os.devnull, "w", encoding="utf-8")  # closed by the caller


def build_mcp_client(server: Any, *, timeout_s: float) -> mcp.Client:
    """The SDK client with ASCA's fixed policy.

    No sampling, elicitation or roots callback is installed, so the SDK refuses those
    server requests. Responses are not cached and log messages are dropped. ``server``
    is a transport (or, in tests, an in-process server).
    """
    return mcp.Client(
        server,
        mode="auto",
        read_timeout_seconds=timeout_s,
        cache=None,
        raise_exceptions=False,
        logging_callback=_drop_log,
        client_info=mcp_types.Implementation(name="asca", version=asca.__version__),
    )


def tools_fingerprint(tools: Iterable[Mapping[str, object]]) -> str:
    """sha256 of the canonical JSON of ``[{name, description, input_schema}]`` sorted by name."""
    entries = sorted(
        (
            {
                "name": tool.get("name"),
                "description": tool.get("description"),
                "input_schema": tool.get("input_schema"),
            }
            for tool in tools
        ),
        key=lambda entry: str(entry["name"]),
    )
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _tool_entry(tool: mcp_types.Tool) -> dict[str, object]:
    return {"name": tool.name, "description": tool.description, "input_schema": tool.input_schema}


def _argument_type(tool: mcp_types.Tool, argument: str) -> object:
    properties = tool.input_schema.get("properties")
    if not isinstance(properties, dict):
        return None
    spec = properties.get(argument)
    return spec.get("type") if isinstance(spec, dict) else None


def _leaves(exc: BaseException) -> list[BaseException]:
    """Flatten nested exception groups iteratively."""
    leaves: list[BaseException] = []
    pending: list[BaseException] = [exc]
    while pending:
        item = pending.pop()
        if isinstance(item, BaseExceptionGroup):
            pending.extend(item.exceptions)
        else:
            leaves.append(item)
    return leaves


_PRIORITY: Final = {
    ProviderErrorKind.AUTH_REQUIRED: 0,
    ProviderErrorKind.NOT_CONFIGURED: 1,
    ProviderErrorKind.TIMEOUT: 2,
    ProviderErrorKind.DNS_FAILED: 3,
    ProviderErrorKind.CONNECT_FAILED: 3,
    ProviderErrorKind.TLS_FAILED: 3,
    ProviderErrorKind.RESPONSE_TOO_LARGE: 3,
    ProviderErrorKind.UNSUPPORTED_ENCODING: 3,
    ProviderErrorKind.MALFORMED_RESPONSE: 4,
    ProviderErrorKind.PROCESS_FAILED: 5,
    ProviderErrorKind.PROTOCOL_ERROR: 6,
}


def _priority(error: ProviderError) -> int:
    if error.code == "process_exited":
        return 7
    return _PRIORITY.get(error.kind, 9)


def _redact_tree(
    value: object, secret: RedactedSecret | None, depth: int = 0
) -> tuple[object, int]:
    """Replace secret echoes in every string of a JSON-like tree; bounded depth."""
    if depth > PAYLOAD_DEPTH_MAX:
        raise _unexpected_payload()
    if isinstance(value, str):
        return redact_echoes(value, secret)
    if isinstance(value, dict):
        result: dict[object, object] = {}
        total = 0
        for key, item in value.items():
            result[key], count = _redact_tree(item, secret, depth + 1)
            total += count
        return result, total
    if isinstance(value, list):
        items: list[object] = []
        total = 0
        for item in value:
            redacted, count = _redact_tree(item, secret, depth + 1)
            items.append(redacted)
            total += count
        return items, total
    return value, 0


@dataclass
class _Observed:
    """What the HTTP response hook saw during one operation (statuses only)."""

    statuses: list[int] = field(default_factory=list)
    resource_metadata: bool = False

    def auth_error(self) -> ProviderError | None:
        if 401 in self.statuses:
            code = "oauth_resource_metadata" if self.resource_metadata else "http_401"
            return _error(ProviderErrorKind.AUTH_REQUIRED, code, 401)
        if 403 in self.statuses:
            return _error(ProviderErrorKind.AUTH_REQUIRED, "http_403", 403)
        return None


@dataclass(frozen=True, slots=True)
class _Session:
    client: mcp.Client
    tools: Mapping[str, mcp_types.Tool]
    secret: RedactedSecret | None


class McpKnowledgeProvider:
    """A configured MCP server as a ``KnowledgeProvider`` (profile ``search_fetch_v1``)."""

    def __init__(
        self,
        settings: McpServerSettings,
        *,
        network: NetworkSettings,
        clock: Clock,
        connector: McpConnector | None = None,
        environ: Mapping[str, str] = os.environ,
        client_factory: ClientFactory = default_client_factory,
    ) -> None:
        self._settings = settings
        self._network = network
        self._clock = clock
        self._connector = connector
        self._environ = environ
        self._client_factory = client_factory
        self._descriptor = ProviderDescriptor(
            id=settings.provider_id,
            kind=ProviderKind.MCP,
            label=f"MCP {settings.server_id}",
            adapter_version=ADAPTER_VERSION,
            access_class=settings.access_class,
            access_conditions=settings.access_conditions,
            max_query_access=settings.max_query_access,
            uses_network=True,
            supports_fetch=settings.fetch_tool is not None,
            timeout_s=settings.timeout_s,
        )

    @property
    def descriptor(self) -> ProviderDescriptor:
        return self._descriptor

    # ------------------------------------------------------------------ operations

    async def search(self, query: KnowledgeQuery) -> SearchOutcome:
        if query.access_class.rank > self._descriptor.max_query_access.rank:
            return _error(ProviderErrorKind.NOT_CONSULTED, "query_access_class")
        settings = self._settings
        arguments: dict[str, object] = {settings.search_query_arg: query.text}
        if settings.search_limit_arg is not None:
            arguments[settings.search_limit_arg] = query.limit

        async def operation(session: _Session) -> SearchResult:
            result = await session.client.call_tool(settings.search_tool, arguments)
            payload, _count = self._payload(result, session.secret)
            return self._search_result(payload, query)

        return await self._run(operation)

    async def fetch(self, ref: CandidateRef) -> FetchOutcome:
        if ref.provider_id != self._descriptor.id or NATIVE_ID_RE.fullmatch(ref.native_id) is None:
            return _error(ProviderErrorKind.UNSUPPORTED, "invalid_native_id")
        fetch_tool = self._settings.fetch_tool
        if fetch_tool is None:
            return _error(ProviderErrorKind.UNSUPPORTED, "fetch_unsupported")
        arguments: dict[str, object] = {self._settings.fetch_id_arg: ref.native_id}

        async def operation(session: _Session) -> FetchResult:
            result = await session.client.call_tool(fetch_tool, arguments)
            payload, count = self._payload(result, session.secret)
            return self._fetch_result(payload, ref, count)

        return await self._run(operation)

    async def health(self, *, deep: bool = False) -> ProviderHealth:
        """Discovery only (the same session setup as search, with no tool call)."""

        async def operation(session: _Session) -> tuple[str, ...]:
            names = {name for name in session.tools if _TOOL_NAME_RE.fullmatch(name)}
            return tuple(sorted(names))

        outcome = await self._run(operation)
        provider_id = self._descriptor.id
        if not isinstance(outcome, ProviderError):
            return ProviderHealth(provider_id, HealthState.AVAILABLE, None, outcome)
        if outcome.kind is ProviderErrorKind.AUTH_REQUIRED:
            state = HealthState.AUTH_REQUIRED
        elif outcome.kind is ProviderErrorKind.NOT_CONFIGURED:
            state = HealthState.MISCONFIGURED
        else:
            state = HealthState.UNAVAILABLE
        return ProviderHealth(provider_id, state, outcome)

    # ------------------------------------------------------------------ session

    async def _run(self, operation: Callable[[_Session], Awaitable[_T]]) -> _T | ProviderError:
        observed = _Observed()
        deadline = asyncio.timeout(self._settings.timeout_s)
        try:
            async with deadline, self._open(observed) as (client, secret):
                tools = await self._discover(client)
                return await operation(_Session(client, tools, secret))
        except Exception as exc:  # mapped to a fixed code; exception text is never used
            return self._map_exception(exc, observed)
        except BaseExceptionGroup:
            if deadline.expired():
                return _error(ProviderErrorKind.TIMEOUT, "provider_timeout")
            raise

    @contextlib.asynccontextmanager
    async def _open(
        self, observed: _Observed
    ) -> AsyncIterator[tuple[mcp.Client, RedactedSecret | None]]:
        settings = self._settings
        if self._connector is not None:
            secret = self._read_token()
            async with self._connector() as client:
                yield client, secret
        elif settings.transport is McpTransport.STREAMABLE_HTTP:
            url = await self._checked_url()
            secret = self._read_token()
            async with self._http_client(url, secret, observed) as http:
                transport = streamable_http_client(
                    url,
                    http_client=http,
                    terminate_on_close=True,
                    max_sse_event_size=SSE_EVENT_MAX_BYTES,
                )
                async with build_mcp_client(transport, timeout_s=settings.timeout_s) as client:
                    yield client, secret
        else:
            command = self._checked_command()
            workdir = tempfile.mkdtemp(prefix="asca-mcp-")
            try:
                os.chmod(workdir, 0o700)
                with _devnull() as errlog:
                    params = mcp.StdioServerParameters(
                        command=sys.executable,
                        args=self._guard_args(command),
                        env=self._child_env(),
                        cwd=workdir,
                    )
                    transport = mcp.stdio_client(params, errlog=errlog)
                    async with build_mcp_client(transport, timeout_s=settings.timeout_s) as client:
                        yield client, None
            finally:
                shutil.rmtree(workdir, ignore_errors=True)

    def _read_token(self) -> RedactedSecret | None:
        name = self._settings.token_env
        if name is None:
            return None
        try:
            secret = read_secret_env(name, self._environ)
        except ValueError:
            raise _refuse(ProviderErrorKind.NOT_CONFIGURED, "token_invalid") from None
        if secret is None:
            raise _refuse(ProviderErrorKind.NOT_CONFIGURED, "token_missing")
        return secret

    async def _checked_url(self) -> str:
        settings = self._settings
        url = settings.url or ""
        try:
            validate_endpoint_url(url, allow_insecure_loopback=settings.allow_insecure_loopback)
            parts = urlsplit(url)
            host = parts.hostname or ""
            port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
            await check_resolved_addresses(
                host,
                port,
                allow_private_network=settings.allow_private_network,
                allow_loopback=settings.allow_insecure_loopback,
                proxied=select_proxy(host, self._network) is not None,
            )
        except UnsafeUrl:
            raise _refuse(ProviderErrorKind.NOT_CONFIGURED, "unsafe_url") from None
        return url

    @contextlib.asynccontextmanager
    async def _http_client(
        self, url: str, secret: RedactedSecret | None, observed: _Observed
    ) -> AsyncIterator[httpx2.AsyncClient]:
        headers = (("Authorization", "Bearer " + secret.reveal()),) if secret else ()
        spec = ClientSpec(
            host=urlsplit(url).hostname or "",
            timeout_s=self._settings.timeout_s,
            max_response_bytes=RESPONSE_MAX_BYTES,
            accept=ACCEPT,
            extra_headers=headers,
        )

        async def record(response: httpx2.Response) -> None:
            observed.statuses.append(response.status_code)
            if response.status_code == 401:
                challenge = response.headers.get("www-authenticate", "")
                observed.resource_metadata = observed.resource_metadata or (
                    "resource_metadata=" in challenge.lower()
                )

        client = self._client_factory(spec, self._network)
        hooks = client.event_hooks
        hooks["response"] = [*hooks.get("response", []), record]
        client.event_hooks = hooks
        async with client:
            yield client

    def _checked_command(self) -> str:
        if os.name != "posix":
            raise _refuse(ProviderErrorKind.PROCESS_FAILED, "platform_unsupported")
        unsafe = _refuse(ProviderErrorKind.NOT_CONFIGURED, "unsafe_command")
        command = self._settings.command
        if command is None:  # pragma: no cover - settings guarantee a command for stdio
            raise unsafe
        resolved = os.path.realpath(command)
        try:
            info = os.stat(resolved)
        except OSError:
            raise unsafe from None
        if (
            not stat.S_ISREG(info.st_mode)
            or not os.access(resolved, os.X_OK)
            or info.st_mode & 0o022
            or info.st_uid not in (os.getuid(), 0)
        ):
            raise unsafe
        return resolved

    def _guard_args(self, command: str) -> list[str]:
        return [
            "-I",
            "-m",
            GUARD_MODULE,
            "--max-line",
            str(GUARD_MAX_LINE),
            "--max-total",
            str(GUARD_MAX_TOTAL),
            "--cpu",
            str(GUARD_CPU_S),
            "--",
            command,
            *self._settings.args,
        ]

    def _child_env(self) -> dict[str, str]:
        """Only the mapped ``ASCA_`` sources.

        The SDK adds HOME, LOGNAME, PATH, SHELL, TERM and USER.
        """
        environ = self._environ
        return {child: environ[source] for child, source in self._settings.env if source in environ}

    async def _discover(self, client: mcp.Client) -> dict[str, mcp_types.Tool]:
        settings = self._settings
        tools: list[mcp_types.Tool] = []
        cursor: str | None = None
        for _ in range(TOOL_PAGES_MAX):
            page = await client.list_tools(cursor=cursor)
            tools.extend(page.tools)
            if len(tools) > TOOLS_MAX:
                break
            cursor = page.next_cursor
            if cursor is None:
                break
        if len(tools) > TOOLS_MAX or cursor is not None:
            raise _refuse(ProviderErrorKind.PROTOCOL_ERROR, "too_many_tools")
        by_name: dict[str, mcp_types.Tool] = {}
        for tool in tools:
            by_name.setdefault(tool.name, tool)
        configured = [settings.search_tool]
        if settings.fetch_tool is not None:
            configured.append(settings.fetch_tool)
        if any(name not in by_name for name in configured):
            raise _refuse(ProviderErrorKind.NOT_CONFIGURED, "tool_missing")
        search = by_name[settings.search_tool]
        expected = [(search, settings.search_query_arg, "string")]
        if settings.search_limit_arg is not None:
            expected.append((search, settings.search_limit_arg, "integer"))
        if settings.fetch_tool is not None:
            expected.append((by_name[settings.fetch_tool], settings.fetch_id_arg, "string"))
        if any(_argument_type(tool, argument) != kind for tool, argument, kind in expected):
            raise _refuse(ProviderErrorKind.NOT_CONFIGURED, "tool_contract_mismatch")
        pin = settings.expected_tools_sha256
        if pin is not None:
            entries = [_tool_entry(by_name[name]) for name in dict.fromkeys(configured)]
            if tools_fingerprint(entries) != pin:
                raise _refuse(ProviderErrorKind.PROTOCOL_ERROR, "tool_schema_changed")
        return by_name

    # ------------------------------------------------------------------ errors

    def _map_exception(self, exc: BaseException, observed: _Observed) -> ProviderError:
        leaves = _leaves(exc)
        for leaf in leaves:
            if isinstance(leaf, _Refused):
                return leaf.error
        auth = observed.auth_error()
        if auth is not None:
            return auth
        return min((self._map_leaf(leaf) for leaf in leaves), key=_priority)

    def _map_leaf(self, leaf: BaseException) -> ProviderError:
        stdio = self._connector is None and self._settings.transport is McpTransport.STDIO
        if isinstance(leaf, TimeoutError | httpx2.TimeoutException):
            return _error(ProviderErrorKind.TIMEOUT, "provider_timeout")
        if isinstance(leaf, mcp.MCPError):
            if leaf.code == mcp_types.REQUEST_TIMEOUT:
                return _error(ProviderErrorKind.TIMEOUT, "provider_timeout")
            if leaf.code == mcp_types.CONNECTION_CLOSED and stdio:
                return _error(ProviderErrorKind.PROCESS_FAILED, "process_exited")
            return _error(ProviderErrorKind.PROTOCOL_ERROR, "mcp_error")
        if isinstance(leaf, httpx2.HTTPError | ResponseTooLarge | UnsupportedEncoding):
            return map_transport_error(leaf)
        if isinstance(leaf, socket.gaierror):
            return _error(ProviderErrorKind.DNS_FAILED, "dns_failed")
        if isinstance(leaf, OSError):
            if stdio:
                return _error(ProviderErrorKind.PROCESS_FAILED, "spawn_failed")
            return _error(ProviderErrorKind.CONNECT_FAILED, "connect_failed")
        if type(leaf).__module__.startswith("anyio") and type(leaf).__name__ in _ANYIO_CLOSED:
            if stdio:
                return _error(ProviderErrorKind.PROCESS_FAILED, "process_exited")
            return _error(ProviderErrorKind.PROTOCOL_ERROR, "mcp_error")
        if isinstance(leaf, ValidationError):
            return _error(ProviderErrorKind.MALFORMED_RESPONSE, "unexpected_payload")
        return _error(ProviderErrorKind.INTERNAL_ERROR, "unexpected_exception")

    # ------------------------------------------------------------------ results

    def _payload(
        self, result: mcp_types.CallToolResult, secret: RedactedSecret | None
    ) -> tuple[dict[object, object], int]:
        if result.is_error:
            raise _refuse(ProviderErrorKind.TOOL_ERROR, "tool_error")
        raw: object
        if isinstance(result.structured_content, dict):
            raw = result.structured_content
        elif len(result.content) == 1 and isinstance(result.content[0], mcp_types.TextContent):
            body = result.content[0].text.encode("utf-8", errors="surrogatepass")
            if len(body) > TEXT_BLOCK_MAX_BYTES:
                raise _unexpected_payload()
            raw = strict_json(body)
        else:
            raise _unexpected_payload()
        if not isinstance(raw, dict):
            raise _unexpected_payload()
        redacted, count = _redact_tree(raw, secret)
        if not isinstance(redacted, dict):  # pragma: no cover - a dict stays a dict
            raise _unexpected_payload()
        return redacted, count

    def _search_result(
        self, payload: Mapping[object, object], query: KnowledgeQuery
    ) -> SearchResult:
        results = payload.get("results")
        if not isinstance(results, list):
            raise _unexpected_payload()
        now = self._clock.now()
        candidates: list[KnowledgeCandidate] = []
        dropped = 0
        for item in results[:RESULTS_MAX]:
            if len(candidates) >= query.limit:
                break
            candidate = self._candidate(item, len(candidates), now)
            if candidate is None:
                dropped += 1
            else:
                candidates.append(candidate)
        return SearchResult(tuple(candidates), len(results), dropped)

    def _fetch_result(
        self, payload: Mapping[object, object], ref: CandidateRef, redactions: int
    ) -> FetchResult:
        if payload.get("id") != ref.native_id:
            raise _unexpected_payload()
        raw_text = payload.get("text")
        if not isinstance(raw_text, str) or (
            len(raw_text.encode("utf-8", errors="surrogatepass")) > DOCUMENT_TEXT_MAX_BYTES
        ):
            raise _unexpected_payload()
        text = clean_block(raw_text, DOCUMENT_TEXT_MAX_BYTES)
        if text is None or len(text.encode("utf-8")) > DOCUMENT_TEXT_MAX_BYTES:
            raise _unexpected_payload()
        now = self._clock.now()
        candidate = self._candidate(payload, 0, now)
        if candidate is None:
            raise _unexpected_payload()
        generated = self._settings.result_kind is McpResultKind.GENERATED
        document = FetchedDocument(
            ref=candidate.ref,
            kind=DocumentKind.GENERATED_TEXT if generated else DocumentKind.TOOL_TEXT,
            media_type=MEDIA_TYPE,
            text=text,
            text_sha256=sha256_text(text),
            raw_sha256=None,
            retrieved_at=now,
            source_url=None,
            access_class=candidate.access_class,
            access_conditions=candidate.access_conditions,
            licenses=(),
            redactions=redactions,
        )
        return FetchResult(candidate, document)

    def _candidate(self, item: object, rank: int, now: datetime) -> KnowledgeCandidate | None:
        """Map one result item; ``None`` when it is invalid (the caller counts it)."""
        if not isinstance(item, dict):
            return None
        native_id = item.get("id")
        title = item.get("title")
        if not isinstance(native_id, str) or NATIVE_ID_RE.fullmatch(native_id) is None:
            return None
        cleaned_title = clean_line(title, TITLE_MAX) if isinstance(title, str) else None
        if cleaned_title is None:
            return None
        url = item.get("url")
        landing = url if isinstance(url, str) and is_https_url(url, LANDING_URL_MAX) else None
        text = item.get("text")
        snippet = clean_block(text, SNIPPET_MAX) if isinstance(text, str) else None
        raw_metadata = item.get("metadata")
        metadata: Mapping[object, object] = raw_metadata if isinstance(raw_metadata, dict) else {}
        access, conditions = self._item_access(metadata)
        settings = self._settings
        generated = settings.result_kind is McpResultKind.GENERATED
        issued = metadata.get("issued")
        try:
            return KnowledgeCandidate(
                ref=CandidateRef(self._descriptor.id, native_id),
                kind=ProviderKind.MCP,
                rank=rank,
                title=cleaned_title[0],
                title_truncated=cleaned_title[1],
                authors=(),
                author_count=None,
                issued=PartialDate.parse(issued) if isinstance(issued, str) else None,
                version=_version(metadata, now),
                pids=_related_pids(metadata, landing),
                landing_url=landing,
                access_class=access,
                access_conditions=conditions,
                facts=PublicationFacts(
                    refereed=None,
                    document_types=(),
                    journal_ref=None,
                    collaborations=(),
                    generated=generated,
                ),
                declared_authority=(
                    SourceAuthority.AUTOMATED_INFERENCE if generated else settings.authority_ceiling
                ),
                content=(
                    ContentAvailability.FULL_TEXT
                    if settings.fetch_tool is not None
                    else ContentAvailability.METADATA_ONLY
                ),
                licenses=(),
                snippet=snippet,
                retrieved_at=now,
            )
        except ValueError:  # pragma: no cover - defensive: every field is validated above
            return None

    def _item_access(self, metadata: Mapping[object, object]) -> tuple[AccessClass, str | None]:
        """An item may only be stricter than the server; an unknown class fails closed."""
        base = self._settings.access_class
        claimed = metadata.get("access_class")
        if claimed is None:
            return base, self._settings.access_conditions
        try:
            item_class = (
                AccessClass(claimed) if isinstance(claimed, str) else AccessClass.RESTRICTED
            )
        except ValueError:
            item_class = AccessClass.RESTRICTED
        effective = most_restrictive((base, item_class))
        if effective is base:
            return base, self._settings.access_conditions
        return effective, self._settings.access_conditions or STRICTER_CONDITIONS


def _version(metadata: Mapping[object, object], now: datetime) -> CandidateVersion:
    declared = metadata.get("version")
    if isinstance(declared, str):
        cleaned = clean_line(declared, VERSION_TEXT_MAX)
        if cleaned is not None:
            with contextlib.suppress(ValueError):
                return CandidateVersion(VersionKind.DECLARED, f"declared:{cleaned[0]}")
    return CandidateVersion(VersionKind.RECORD_SNAPSHOT, f"retrieved@{now.date().isoformat()}")


def _related_pids(
    metadata: Mapping[object, object], landing: str | None
) -> tuple[CandidatePid, ...]:
    """Metadata identifiers and the item URL, as RELATED provider-asserted pids only."""
    found: list[PersistentIdentifier] = []
    doi = metadata.get("doi")
    if isinstance(doi, str) and (pid := normalize_doi(doi)) is not None:
        found.append(pid)
    for key in ("arxiv", "arxiv_id"):
        value = metadata.get(key)
        if isinstance(value, str) and (arxiv := normalize_arxiv(value)) is not None:
            found.append(arxiv[0])
    for key in ("inspire", "recid"):
        value = metadata.get(key)
        if (
            isinstance(value, int | str)
            and not isinstance(value, bool)
            and (inspire := normalize_inspire(value)) is not None
        ):
            found.append(inspire)
    report = metadata.get("cds_report")
    if isinstance(report, str) and (normalized := normalize_report_number(report)) is not None:
        found.append(normalized[0])
    if landing is not None:
        with contextlib.suppress(ValueError):
            found.append(PersistentIdentifier(PidScheme.URL, landing))
    unique = {(pid.scheme, pid.value): pid for pid in found}
    ordered = sorted(unique.values(), key=pid_sort_key)
    return tuple(CandidatePid(pid, PidRole.RELATED, PidOrigin.PROVIDER_ASSERTED) for pid in ordered)
