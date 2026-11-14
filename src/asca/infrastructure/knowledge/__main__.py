"""Knowledge CLI: ``python -m asca.infrastructure.knowledge`` (prog ``asca-knowledge``).

Commands: ``search``, ``fetch``, ``health`` and ``providers``. Every network call needs
``--live``; without it network providers are reported as skipped and never called. The
CLI never prompts, never accepts a token on the command line, prints usage and
configuration errors as fixed messages without echoing values, and treats every
provider string as data: text output escapes control, bidi and invisible characters and
prefixes titles and snippets with ``provider data:``.

Exit codes: ``search`` 0 when every selected provider is OK, 3 when some but not all
are OK or PARTIAL, 4 when none is; ``fetch`` 0 or 4; ``health`` 0 when every provider is
AVAILABLE or NOT_PROBED, else 3; ``providers`` 0; 2 for a usage or configuration error.
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Final, NoReturn, Protocol, TextIO

from asca.application.knowledge.federation import (
    AssessedCandidate,
    EvidenceGroup,
    FederatedSearchResult,
    FederationService,
    ProviderReport,
    ProviderStatus,
)
from asca.application.knowledge.models import (
    QUERY_LIMIT_MAX,
    CandidateRef,
    FetchedDocument,
    FetchResult,
    HealthState,
    KnowledgeCandidate,
    KnowledgeQuery,
    LicenseInfo,
    ProviderError,
    ProviderHealth,
)
from asca.application.knowledge.pids import pid_text
from asca.application.knowledge.policy import AuthoritySuggestion, suggest_authority
from asca.application.knowledge.text import terminal_safe
from asca.application.ports import Clock
from asca.domain.provenance import AccessClass
from asca.infrastructure.knowledge.config import (
    KnowledgeConfigError,
    effective_precedence,
    load_settings,
)
from asca.infrastructure.knowledge.factory import build_federation
from asca.infrastructure.knowledge.settings import (
    KnowledgeSettings,
    McpServerSettings,
    McpTransport,
)

PROG: Final = "asca-knowledge"
SEARCH_FORMAT: Final = "asca-knowledge-search/1"
FETCH_FORMAT: Final = "asca-knowledge-fetch/1"
HEALTH_FORMAT: Final = "asca-knowledge-health/1"
PROVIDERS_FORMAT: Final = "asca-knowledge-providers/1"
EXIT_OK: Final = 0
EXIT_USAGE: Final = 2
EXIT_PARTIAL: Final = 3
EXIT_FAILED: Final = 4
QUIET_LOGGERS: Final = ("httpx2", "httpcore2", "mcp", "asyncio")
LIVE_NOTE: Final = "note: network providers need --live"
DATA_PREFIX: Final = "provider data: "
_HEALTHY: Final = frozenset({HealthState.AVAILABLE, HealthState.NOT_PROBED})
_USABLE: Final = frozenset({ProviderStatus.OK, ProviderStatus.PARTIAL})


class FederationBuilder(Protocol):
    """Builds the federation from settings; the default wraps ``factory.build_federation``."""

    def __call__(
        self, settings: KnowledgeSettings, *, live: bool, clock: Clock
    ) -> FederationService: ...


class _UsageError(Exception):
    """A usage error; the message is fixed and never echoes a value."""

    def __init__(self, message: str = "invalid command line") -> None:
        super().__init__(message)
        self.message = message


class _UtcClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


def _default_builder(environ: Mapping[str, str]) -> FederationBuilder:
    """``build_federation`` with the CLI's environment (for MCP token and child variables)."""

    def build(settings: KnowledgeSettings, *, live: bool, clock: Clock) -> FederationService:
        return build_federation(settings, live=live, clock=clock, environ=environ)

    return build


class _Parser(argparse.ArgumentParser):
    """``argparse`` whose errors never echo the offending value."""

    def error(self, message: str) -> NoReturn:
        raise _UsageError


def _limit(text: str) -> int:
    if not (text.isascii() and text.isdigit()) or not 1 <= int(text) <= QUERY_LIMIT_MAX:
        raise argparse.ArgumentTypeError("invalid limit")
    return int(text)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog=PROG, description="Search public and configured knowledge sources.")
    parser.add_argument("--config", metavar="PATH", help="configuration file (TOML)")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    formats = ("json", "text")

    search = commands.add_parser("search", help="search every selected provider")
    search.add_argument("query", metavar="QUERY")
    search.add_argument("--live", action="store_true", help="allow network calls")
    search.add_argument("--providers", metavar="ID[,ID...]")
    search.add_argument("--limit", type=_limit, default=5)
    search.add_argument(
        "--query-class", choices=[item.value for item in AccessClass], default="public"
    )
    search.add_argument("--format", choices=formats, default="json")
    search.add_argument("--timings", action="store_true", help="include elapsed_ms")

    fetch = commands.add_parser("fetch", help="fetch one record by provider and native id")
    fetch.add_argument("provider_id", metavar="PROVIDER_ID")
    fetch.add_argument("native_id", metavar="NATIVE_ID")
    fetch.add_argument("--live", action="store_true", help="allow network calls")
    fetch.add_argument("--format", choices=formats, default="json")
    fetch.add_argument("--print-text", action="store_true", help="include the document text")

    health = commands.add_parser("health", help="report provider health")
    health.add_argument("--live", action="store_true", help="allow network calls")
    health.add_argument("--deep", action="store_true", help="run deeper checks")
    health.add_argument("--format", choices=formats, default="json")

    providers = commands.add_parser("providers", help="show the effective settings")
    providers.add_argument("--format", choices=formats, default="json")
    return parser


# ---------------------------------------------------------------------- JSON views


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def error_view(error: ProviderError | None) -> dict[str, object] | None:
    if error is None:
        return None
    return {
        "kind": error.kind.value,
        "code": error.code,
        "http_status": error.http_status,
        "retry_after_s": error.retry_after_s,
    }


def _license_view(item: LicenseInfo) -> dict[str, object]:
    return {"identifier": item.identifier, "url": item.url, "scope": item.scope.value}


def _suggestion_view(suggestion: AuthoritySuggestion) -> dict[str, object]:
    return {
        "authority": suggestion.authority.value,
        "letter": suggestion.authority.letter,
        "rule": suggestion.rule.value,
        "basis": suggestion.basis,
    }


def candidate_view(
    candidate: KnowledgeCandidate, suggestion: AuthoritySuggestion
) -> dict[str, object]:
    facts = candidate.facts
    return {
        "provider": candidate.ref.provider_id,
        "native_id": candidate.ref.native_id,
        "rank": candidate.rank,
        "title": candidate.title,
        "title_truncated": candidate.title_truncated,
        "authors": list(candidate.authors),
        "author_count": candidate.author_count,
        "issued": None if candidate.issued is None else candidate.issued.iso(),
        "version": {"kind": candidate.version.kind.value, "label": candidate.version.label},
        "pids": [
            {"pid": pid_text(item.pid), "role": item.role.value, "origin": item.origin.value}
            for item in candidate.pids
        ],
        "landing_url": candidate.landing_url,
        "access_class": candidate.access_class.value,
        "access_conditions": candidate.access_conditions,
        "facts": {
            "refereed": facts.refereed,
            "document_types": list(facts.document_types),
            "journal_ref": facts.journal_ref,
            "collaborations": list(facts.collaborations),
            "generated": facts.generated,
        },
        "suggestion": _suggestion_view(suggestion),
        "content": candidate.content.value,
        "licenses": [_license_view(item) for item in candidate.licenses],
        "snippet": candidate.snippet,
        "retrieved_at": _timestamp(candidate.retrieved_at),
    }


def _member_view(member: AssessedCandidate) -> dict[str, object]:
    return candidate_view(member.candidate, member.suggestion)


def _group_view(group: EvidenceGroup) -> dict[str, object]:
    return {
        "key": group.key,
        "identity_pids": [pid_text(pid) for pid in group.identity_pids],
        "flags": sorted(flag.value for flag in group.flags),
        "effective_access_class": group.effective_access_class.value,
        "best_rank": group.best_rank,
        "members": [_member_view(member) for member in group.members],
    }


def _report_view(report: ProviderReport, timings: bool) -> dict[str, object]:
    view: dict[str, object] = {
        "id": report.provider_id,
        "kind": report.kind.value,
        "status": report.status.value,
        "returned": report.returned,
        "dropped_items": report.dropped_items,
        "total_reported": report.total_reported,
        "error": error_view(report.error),
    }
    if timings:
        view["elapsed_ms"] = report.elapsed_ms
    return view


def search_view(result: FederatedSearchResult, *, timings: bool = False) -> dict[str, object]:
    query = result.query
    return {
        "format": SEARCH_FORMAT,
        "query": {
            "text": query.text,
            "limit": query.limit,
            "access_class": query.access_class.value,
        },
        "complete": result.complete,
        "providers": [_report_view(report, timings) for report in result.reports],
        "groups": [_group_view(group) for group in result.groups],
    }


def _document_view(document: FetchedDocument, print_text: bool) -> dict[str, object]:
    view: dict[str, object] = {
        "kind": document.kind.value,
        "media_type": document.media_type,
        "text_sha256": document.text_sha256,
        "raw_sha256": document.raw_sha256,
        "length": len(document.text),
        "retrieved_at": _timestamp(document.retrieved_at),
        "source_url": document.source_url,
        "access_class": document.access_class.value,
        "access_conditions": document.access_conditions,
        "licenses": [_license_view(item) for item in document.licenses],
        "redactions": document.redactions,
    }
    if print_text:
        view["text"] = document.text
    return view


def fetch_view(
    ref: CandidateRef, outcome: FetchResult | ProviderError, *, print_text: bool = False
) -> dict[str, object]:
    view: dict[str, object] = {
        "format": FETCH_FORMAT,
        "ref": {"provider": ref.provider_id, "native_id": ref.native_id},
    }
    if isinstance(outcome, ProviderError):
        view.update(candidate=None, document=None, error=error_view(outcome))
        return view
    candidate = outcome.candidate
    view.update(
        candidate=candidate_view(candidate, suggest_authority(candidate)),
        document=_document_view(outcome.document, print_text),
        error=None,
    )
    return view


def health_view(results: Sequence[ProviderHealth], *, live: bool, deep: bool) -> dict[str, object]:
    return {
        "format": HEALTH_FORMAT,
        "live": live,
        "deep": deep,
        "providers": [
            {
                "id": item.provider_id,
                "state": item.state.value,
                "error": error_view(item.error),
                "tool_names": list(item.tool_names),
            }
            for item in results
        ],
    }


def _secret_name(name: str | None, environ: Mapping[str, str]) -> str | None:
    """The variable NAME and whether it is set; never its value."""
    if name is None:
        return None
    return f"{name} ({'set' if environ.get(name) else 'unset'})"


def _mcp_view(server: McpServerSettings, environ: Mapping[str, str]) -> dict[str, object]:
    view: dict[str, object] = {
        "id": server.provider_id,
        "kind": "mcp",
        "enabled": server.enabled,
        "timeout_s": server.timeout_s,
        "transport": server.transport.value,
        "access_class": server.access_class.value,
        "access_conditions": server.access_conditions,
        "max_query_access": server.max_query_access.value,
        "authority_ceiling": server.authority_ceiling.value,
        "result_kind": server.result_kind.value,
        "search_tool": server.search_tool,
        "search_query_arg": server.search_query_arg,
        "search_limit_arg": server.search_limit_arg,
        "fetch_tool": server.fetch_tool,
        "fetch_id_arg": server.fetch_id_arg,
        "expected_tools_sha256": server.expected_tools_sha256,
    }
    if server.transport is McpTransport.STREAMABLE_HTTP:
        view.update(
            url=server.url,
            token_env=_secret_name(server.token_env, environ),
            allow_private_network=server.allow_private_network,
            allow_insecure_loopback=server.allow_insecure_loopback,
        )
    else:
        view.update(
            command=server.command,
            args=list(server.args),
            env=[
                {"name": child, "source": _secret_name(source, environ)}
                for child, source in server.env
            ],
        )
    return view


def providers_view(settings: KnowledgeSettings, environ: Mapping[str, str]) -> dict[str, object]:
    network = settings.network
    entries: list[dict[str, object]] = [
        {"id": "inspire", "kind": "inspire", **_basic(settings.inspire)},
        {
            "id": "arxiv",
            "kind": "arxiv",
            **_basic(settings.arxiv),
            "min_interval_s": settings.arxiv.min_interval_s,
        },
        {"id": "hepdata", "kind": "hepdata", **_basic(settings.hepdata)},
    ]
    if settings.local is not None:
        entries.append(
            {"id": "local", "kind": "local", **_basic(settings.local), "root": settings.local.root}
        )
    entries += [_mcp_view(server, environ) for server in settings.mcp]
    order = {item: index for index, item in enumerate(effective_precedence(settings))}
    entries.sort(key=lambda entry: order[str(entry["id"])])
    return {
        "format": PROVIDERS_FORMAT,
        "precedence": list(effective_precedence(settings)),
        "network": {"proxy": network.proxy_mode.value, "proxy_url": network.proxy_url},
        "providers": entries,
    }


class _Basic(Protocol):
    @property
    def enabled(self) -> bool: ...

    @property
    def timeout_s(self) -> float: ...


def _basic(item: _Basic) -> dict[str, object]:
    return {"enabled": item.enabled, "timeout_s": item.timeout_s}


def dumps(view: Mapping[str, object]) -> str:
    return json.dumps(view, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------- text views


def _error_text(error: ProviderError | None) -> str:
    return "" if error is None else f"{error.kind.value}/{error.code}"


def _one_line(value: str) -> str:
    return " ".join(value.split())


def _not_consulted_line(reports: Sequence[ProviderReport]) -> str:
    items = [
        f"{report.provider_id} ({_error_text(report.error)})"
        for report in reports
        if report.status in (ProviderStatus.FAILED, ProviderStatus.SKIPPED)
    ]
    return "Sources not consulted: " + (", ".join(items) if items else "none")


def _candidate_lines(candidate: KnowledgeCandidate, suggestion: AuthoritySuggestion) -> list[str]:
    lines = [
        f"  - {candidate.ref.provider_id} {candidate.ref.native_id} rank {candidate.rank}"
        f" | {candidate.version.label} | suggests {suggestion.authority.letter}"
        f" ({suggestion.rule.value}) | access {candidate.access_class.value}",
        f"    {DATA_PREFIX}{candidate.title}",
    ]
    if candidate.snippet is not None:
        lines.append(f"    {DATA_PREFIX}{_one_line(candidate.snippet)}")
    return lines


def search_text(result: FederatedSearchResult, *, timings: bool = False) -> str:
    query = result.query
    lines = [f"query: {query.text} (limit {query.limit}, query class {query.access_class.value})"]
    for report in result.reports:
        line = f"provider {report.provider_id}: {report.status.value}"
        if report.error is not None:
            line += f" ({_error_text(report.error)})"
        else:
            line += f", returned {report.returned}, dropped {report.dropped_items}"
        if timings:
            line += f", {report.elapsed_ms} ms"
        lines.append(line)
    for index, group in enumerate(result.groups, start=1):
        flags = ",".join(sorted(flag.value for flag in group.flags)) or "none"
        lines.append(
            f"group {index}: {group.key} | access {group.effective_access_class.value}"
            f" | flags {flags}"
        )
        for member in group.members:
            lines += _candidate_lines(member.candidate, member.suggestion)
    lines.append(_not_consulted_line(result.reports))
    return _safe_lines(lines)


def fetch_text(
    ref: CandidateRef, outcome: FetchResult | ProviderError, *, print_text: bool = False
) -> str:
    lines = [f"fetch: {ref.provider_id} {ref.native_id}"]
    if isinstance(outcome, ProviderError):
        lines.append(f"error: {_error_text(outcome)}")
        return _safe_lines(lines)
    candidate, document = outcome.candidate, outcome.document
    lines += _candidate_lines(candidate, suggest_authority(candidate))
    lines.append(
        f"document: {document.kind.value} | {document.media_type} | {len(document.text)}"
        f" characters | sha256 {document.text_sha256} | access {document.access_class.value}"
    )
    output = _safe_lines(lines)
    if print_text:
        output += DATA_PREFIX + "\n" + terminal_safe(document.text)
        if not output.endswith("\n"):
            output += "\n"
    return output


def health_text(results: Sequence[ProviderHealth]) -> str:
    lines = []
    for item in results:
        line = f"provider {item.provider_id}: {item.state.value}"
        if item.error is not None:
            line += f" ({_error_text(item.error)})"
        if item.tool_names:
            line += f" | tools {', '.join(item.tool_names)}"
        lines.append(line)
    return _safe_lines(lines)


def providers_text(view: Mapping[str, object]) -> str:
    lines = [f"precedence: {', '.join(str(item) for item in _list(view['precedence']))}"]
    for entry in _list(view["providers"]):
        assert isinstance(entry, dict)
        details = ", ".join(
            f"{key}={_compact(value)}" for key, value in sorted(entry.items()) if key != "id"
        )
        lines.append(f"provider {entry['id']}: {details}")
    return _safe_lines(lines)


def _list(value: object) -> list[object]:
    assert isinstance(value, list)
    return value


def _compact(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _safe_lines(lines: Sequence[str]) -> str:
    """One output line per entry; every provider string is escaped for the terminal."""
    return "".join(terminal_safe(line.replace("\n", " ")) + "\n" for line in lines)


# ---------------------------------------------------------------------- commands


def _quiet_loggers() -> None:
    for name in QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def _search_exit(reports: Sequence[ProviderReport]) -> int:
    usable = sum(1 for report in reports if report.status in _USABLE)
    if reports and all(report.status is ProviderStatus.OK for report in reports):
        return EXIT_OK
    return EXIT_PARTIAL if usable else EXIT_FAILED


def _only(raw: str | None, federation: FederationService) -> frozenset[str] | None:
    if raw is None:
        return None
    selected = frozenset(item.strip() for item in raw.split(","))
    if not selected or not selected <= set(federation.order):
        raise _UsageError("unknown provider id in --providers")
    return selected


def _live_note(errors: Iterable[ProviderError | None], err: TextIO) -> None:
    """Print the ``--live`` note when a network provider was skipped for that reason."""
    if any(error is not None and error.code == "live_disabled" for error in errors):
        err.write(LIVE_NOTE + "\n")


def _run_search(
    args: argparse.Namespace, federation: FederationService, out: TextIO, err: TextIO
) -> int:
    try:
        query = KnowledgeQuery(args.query.strip(), args.limit, AccessClass(args.query_class))
    except ValueError:
        raise _UsageError("invalid query") from None
    only = _only(args.providers, federation)
    result = asyncio.run(federation.search(query, only=only))
    _live_note((report.error for report in result.reports), err)
    if args.format == "text":
        out.write(search_text(result, timings=args.timings))
    else:
        out.write(dumps(search_view(result, timings=args.timings)))
    return _search_exit(result.reports)


def _run_fetch(
    args: argparse.Namespace, federation: FederationService, out: TextIO, err: TextIO
) -> int:
    try:
        ref = CandidateRef(args.provider_id, args.native_id)
    except ValueError:
        raise _UsageError("invalid provider id or native id") from None
    outcome = asyncio.run(federation.fetch(ref))
    _live_note([outcome if isinstance(outcome, ProviderError) else None], err)
    if args.format == "text":
        out.write(fetch_text(ref, outcome, print_text=args.print_text))
    else:
        out.write(dumps(fetch_view(ref, outcome, print_text=args.print_text)))
    return EXIT_FAILED if isinstance(outcome, ProviderError) else EXIT_OK


def _run_health(
    args: argparse.Namespace, federation: FederationService, out: TextIO, err: TextIO
) -> int:
    results = asyncio.run(federation.health(deep=args.deep))
    _live_note((item.error for item in results), err)
    if args.format == "text":
        out.write(health_text(results))
    else:
        out.write(dumps(health_view(results, live=args.live, deep=args.deep)))
    return EXIT_OK if all(item.state in _HEALTHY for item in results) else EXIT_PARTIAL


Runner = Callable[[argparse.Namespace, FederationService, TextIO, TextIO], int]
_RUNNERS: Final[dict[str, Runner]] = {
    "search": _run_search,
    "fetch": _run_fetch,
    "health": _run_health,
}


def main(
    argv: Sequence[str] | None = None,
    *,
    build: FederationBuilder | None = None,
    environ: Mapping[str, str] | None = None,
    clock: Clock | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run one command and return its exit code; never prompts, never raises on input."""
    out = sys.stdout if stdout is None else stdout
    err = sys.stderr if stderr is None else stderr
    env = os.environ if environ is None else environ
    _quiet_loggers()
    try:
        args = _parser().parse_args(argv)
    except _UsageError as error:
        err.write(f"{PROG}: error: {error.message} (see --help)\n")
        return EXIT_USAGE
    except SystemExit as stop:  # --help
        return stop.code if isinstance(stop.code, int) else EXIT_USAGE
    try:
        settings = load_settings(args.config, env)
    except KnowledgeConfigError as error:
        err.write(f"{PROG}: error: {error}\n")
        for detail in error.details:
            err.write(f"{PROG}:   {terminal_safe(detail)}\n")
        return EXIT_USAGE
    if args.command == "providers":
        view = providers_view(settings, env)
        out.write(providers_text(view) if args.format == "text" else dumps(view))
        return EXIT_OK
    builder = _default_builder(env) if build is None else build
    try:
        federation = builder(settings, live=args.live, clock=clock or _UtcClock())
        return _RUNNERS[args.command](args, federation, out, err)
    except _UsageError as error:
        err.write(f"{PROG}: error: {error.message}\n")
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
