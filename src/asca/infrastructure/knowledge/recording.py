"""Fixture recorder for the public providers (format ``asca-http-fixture/1``).

Opt-in and never in CI: ``run`` refuses without ``live`` and whenever ``CI`` is set. The
scenarios are a fixed table built from the adapters' own request builders, so replay keys
match exactly; there are no free-form URLs, and MCP and the local library are never
recorded. Recording is polite (generic User-Agent, one connection, at least 3 s between
arXiv requests and 1 s between any requests) and licence-clean:

- INSPIRE abstracts and arXiv summaries are replaced with a synthetic sentence;
- author lists are cut to three names; arXiv affiliations and comments are removed;
- a Cloudflare challenge body is replaced with a fixed placeholder;
- only allowlisted response headers are kept, and request headers are never stored.

Every fixture passes the write checks (size, header allowlist, credential, email and
ORCID patterns, no 40-character remnant of an original abstract, no overwrite without
``force``) before anything is written; one failure refuses the whole run. The maintainer
reviews the diff before committing.
"""

import asyncio
import hashlib
import json
import logging
import re
import sys
import time
import xml.etree.ElementTree as StdElementTree
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, TextIO
from urllib.parse import urlsplit, urlunsplit

import httpx2
from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

from asca.application.knowledge.models import KnowledgeQuery
from asca.application.ports import Clock
from asca.infrastructure.knowledge import arxiv, hepdata, inspire
from asca.infrastructure.knowledge.http import (
    ClientFactory,
    ClientSpec,
    ResponseTooLarge,
    UnsupportedEncoding,
    default_client_factory,
    strict_json,
)
from asca.infrastructure.knowledge.settings import NetworkSettings

FIXTURE_FORMAT: Final = "asca-http-fixture/1"
RECORDER: Final = "asca-recorder/1"
SYNTHETIC_RECORDER: Final = "asca-synthetic/1"
EXIT_QUERY: Final = "energy reconstruction liquid argon calorimeter neural network"
EXIT_LIMIT: Final = 5
BODY_MAX_BYTES: Final = 65_536
TOTAL_MAX_BYTES: Final = 262_144
CAPTURE_MAX_BYTES: Final = 2_097_152
CAPTURE_TIMEOUT_S: Final = 30.0
AUTHORS_KEPT: Final = 3
ABSTRACT_WINDOW: Final = 40
ARXIV_GAP_S: Final = 3.0
REQUEST_GAP_S: Final = 1.0
KEPT_HEADERS: Final = (
    "content-type",
    "retry-after",
    "cf-mitigated",
    "www-authenticate",
    "location",
)
FORBIDDEN_RE: Final = re.compile(r"(?i)authorization|bearer\s|set-cookie|eyJ[A-Za-z0-9_-]{10,}\.")
EMAIL_RE: Final = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
# Matches exactly when EMAIL_RE does, in linear time: EMAIL_RE backtracks quadratically over
# long runs of word characters without an "@".
_EMAIL_AT_RE: Final = re.compile(r"(?<=[\w.+-])@[\w-]+\.[\w.]+")
ORCID_RE: Final = re.compile(r"(?i)orcid")
SYNTHETIC_ABSTRACT: Final = (
    "Synthetic abstract replacing the original text of record {record} for licence reasons. "
    "Optimal filtering minimises the noise variance of the amplitude estimate."
)
CHALLENGE_BODY: Final = "<html>Cloudflare challenge body removed</html>"
EXIT_REFUSED: Final = 2
EXIT_CHECK_FAILED: Final = 1


@dataclass(frozen=True, slots=True)
class ProviderTerms:
    base_url: str
    metadata_license: str
    terms_url: str
    accept: str


PUBLIC_PROVIDERS: Final[Mapping[str, ProviderTerms]] = {
    "inspire": ProviderTerms(
        inspire.INSPIRE_API,
        "CC0-1.0",
        "https://inspirehep.net/help/knowledge-base/terms-of-use",
        "application/json",
    ),
    "arxiv": ProviderTerms(
        arxiv.ARXIV_API,
        "CC0-1.0 (metadata)",
        "https://info.arxiv.org/help/api/tou.html",
        arxiv.ATOM_CONTENT_TYPE,
    ),
    "hepdata": ProviderTerms(
        hepdata.HEPDATA_SEARCH, "CC0-1.0", "https://www.hepdata.net/terms", "application/json"
    ),
}


class RecordingRefused(Exception):  # noqa: N818 - a refusal, not an internal error
    """The recorder refuses to record or to write; the message never echoes provider data."""


@dataclass(frozen=True, slots=True)
class Scenario:
    provider: str
    name: str
    url: str
    params: tuple[tuple[str, str], ...]
    expect_challenge: bool = False

    def __post_init__(self) -> None:
        terms = PUBLIC_PROVIDERS.get(self.provider)
        if terms is None:
            raise RecordingRefused("the recorder records public providers only")
        if self.url != terms.base_url:
            raise RecordingRefused("a scenario must use its provider's fixed base URL")

    @property
    def key(self) -> str:
        return f"{self.provider}/{self.name}"


_EXIT = KnowledgeQuery(EXIT_QUERY, EXIT_LIMIT)
_ARXIV_SEARCH = arxiv.search_params(_EXIT) or ()
SCENARIOS: Final = (
    Scenario("inspire", "lar_nn_search", inspire.INSPIRE_API, inspire.search_params(_EXIT)),
    Scenario("inspire", "fetch_1920956", inspire.INSPIRE_API, inspire.fetch_params("1920956")),
    Scenario("arxiv", "lar_nn_search", arxiv.ARXIV_API, _ARXIV_SEARCH),
    Scenario("arxiv", "fetch_2109.05124v2", arxiv.ARXIV_API, arxiv.fetch_params("2109.05124v2")),
    Scenario("arxiv", "fetch_unknown", arxiv.ARXIV_API, arxiv.fetch_params("9912.99999")),
    Scenario(
        "hepdata",
        "lar_nn_search_blocked",
        hepdata.HEPDATA_SEARCH,
        hepdata.search_params(EXIT_QUERY, EXIT_LIMIT),
        expect_challenge=True,
    ),
)
SCENARIO_NAMES: Final = tuple(scenario.key for scenario in SCENARIOS)


@dataclass(frozen=True, slots=True)
class Exchange:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


@dataclass(frozen=True, slots=True)
class Sanitized:
    body_text: str
    notes: tuple[str, ...]
    originals: tuple[str, ...]
    """Original abstract texts, used only for the remnant check; never written."""
    exempt: tuple[str, ...] = ()
    """Kept CC0 metadata (titles) masked before the remnant check: abstracts often repeat
    their title, which is not abstract text."""


class _UtcClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


# ---------------------------------------------------------------------- headers


def kept_headers(headers: Iterable[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    """Allowlisted response headers only (lowercased); ``location`` loses its query."""
    kept: dict[str, str] = {}
    for name, value in headers:
        lowered = name.lower()
        if lowered not in KEPT_HEADERS or lowered in kept:
            continue
        if lowered == "location":
            parts = urlsplit(value)
            value = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        kept[lowered] = value
    return tuple(sorted(kept.items()))


def is_challenge(headers: Iterable[tuple[str, str]]) -> bool:
    return any(
        name.lower() == "cf-mitigated" and value.strip().lower() == "challenge"
        for name, value in headers
    )


# ---------------------------------------------------------------------- sanitizers


def _truncate_authors(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: (
                [_truncate_authors(item) for item in child[:AUTHORS_KEPT]]
                if key == "authors" and isinstance(child, list)
                else _truncate_authors(child)
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_truncate_authors(item) for item in value]
    return value


def sanitize_inspire(body: bytes) -> Sanitized:
    """Replace every ``abstracts[].value``; cut every ``authors`` list to three."""
    document = strict_json(body)
    if not isinstance(document, dict):
        raise RecordingRefused("INSPIRE response is not a JSON object")
    originals: list[str] = []
    exempt: list[str] = []
    hits = document.get("hits")
    entries = hits.get("hits") if isinstance(hits, dict) else None
    for hit in entries if isinstance(entries, list) else []:
        metadata = hit.get("metadata") if isinstance(hit, dict) else None
        if not isinstance(metadata, dict):
            continue
        record = metadata.get("control_number")
        for title in metadata.get("titles") or []:
            if isinstance(title, dict) and isinstance(title.get("title"), str):
                exempt.append(title["title"])
        for abstract in metadata.get("abstracts") or []:
            if isinstance(abstract, dict) and isinstance(abstract.get("value"), str):
                replacement = SYNTHETIC_ABSTRACT.format(record=record)
                if abstract["value"] != replacement:
                    originals.append(abstract["value"])
                abstract["value"] = replacement
    text = json.dumps(
        _truncate_authors(document), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    notes = ("abstracts replaced with synthetic text", f"authors truncated to {AUTHORS_KEPT}")
    return Sanitized(text, notes, tuple(originals), tuple(exempt))


def _tag(namespace: str, name: str) -> str:
    return f"{{{namespace}}}{name}"


def sanitize_arxiv(body: bytes) -> Sanitized:
    """Replace every ``<summary>``; keep three authors; drop affiliations and comments."""
    head = body[: arxiv.PRECHECK_BYTES]
    if b"<!DOCTYPE" in head or b"<!ENTITY" in head:
        raise RecordingRefused("arXiv response declares a DTD or an entity")
    try:
        root = fromstring(body, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (DefusedXmlException, ParseError, ValueError):
        raise RecordingRefused("arXiv response is not well-formed XML") from None
    originals: list[str] = []
    exempt: list[str] = []
    for entry in root.findall(_tag(arxiv.ATOM, "entry")):
        record = (entry.findtext(_tag(arxiv.ATOM, "id")) or "").strip().rsplit("/abs/", 1)[-1]
        exempt.extend(title.text or "" for title in entry.findall(_tag(arxiv.ATOM, "title")))
        replacement = SYNTHETIC_ABSTRACT.format(record=record)
        for summary in entry.findall(_tag(arxiv.ATOM, "summary")):
            if summary.text != replacement:
                originals.append(summary.text or "")
            summary.text = replacement
        for comment in entry.findall(_tag(arxiv.ARXIV_NS, "comment")):
            entry.remove(comment)
        for index, author in enumerate(entry.findall(_tag(arxiv.ATOM, "author"))):
            if index >= AUTHORS_KEPT:
                entry.remove(author)
                continue
            for affiliation in author.findall(_tag(arxiv.ARXIV_NS, "affiliation")):
                author.remove(affiliation)
    StdElementTree.register_namespace("", arxiv.ATOM)
    StdElementTree.register_namespace("arxiv", arxiv.ARXIV_NS)
    StdElementTree.register_namespace("opensearch", arxiv.OPENSEARCH)
    text = StdElementTree.tostring(root, encoding="unicode")
    notes = (
        "summaries replaced with synthetic text",
        f"authors truncated to {AUTHORS_KEPT}",
        "affiliations and comments removed",
    )
    return Sanitized(text, notes, tuple(originals), tuple(exempt))


def sanitize(scenario: Scenario, exchange: Exchange) -> Sanitized:
    challenge = is_challenge(exchange.headers)
    if scenario.expect_challenge != challenge:
        raise RecordingRefused(f"{scenario.key}: unexpected challenge state")
    if challenge:
        return Sanitized(CHALLENGE_BODY, ("challenge body replaced",), ())
    if exchange.status != 200:
        raise RecordingRefused(f"{scenario.key}: unexpected HTTP status {exchange.status}")
    if scenario.provider == "inspire":
        return sanitize_inspire(exchange.body)
    if scenario.provider == "arxiv":
        return sanitize_arxiv(exchange.body)
    raise RecordingRefused(f"{scenario.key}: no sanitizer for a successful response")


# ---------------------------------------------------------------------- documents and checks


def fixture_document(
    *,
    provider: str,
    scenario: str,
    url: str,
    params: Iterable[tuple[str, str]],
    status: int,
    headers: Iterable[tuple[str, str]],
    body_text: str,
    sanitized: Iterable[str],
    recorded_at: datetime,
    synthetic: bool,
) -> dict[str, object]:
    """One ``asca-http-fixture/1`` document; params sorted, headers allowlisted."""
    terms = PUBLIC_PROVIDERS.get(provider)
    if terms is None:
        raise RecordingRefused("fixtures exist for public providers only")
    return {
        "format": FIXTURE_FORMAT,
        "provider": provider,
        "scenario": scenario,
        "synthetic": synthetic,
        "recorded_at": recorded_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "recorder": SYNTHETIC_RECORDER if synthetic else RECORDER,
        "metadata_license": terms.metadata_license,
        "terms_url": terms.terms_url,
        "sanitized": list(sanitized),
        "request": {
            "method": "GET",
            "url": url,
            "params": [list(pair) for pair in sorted(params)],
        },
        "response": {
            "status": status,
            "headers": dict(kept_headers(headers)),
            "body_text": body_text,
            "body_sha256": hashlib.sha256(body_text.encode("utf-8")).hexdigest(),
        },
    }


def _remnant(original: str, text: str) -> bool:
    return any(
        original[start : start + ABSTRACT_WINDOW] in text
        for start in range(len(original) - ABSTRACT_WINDOW + 1)
    )


def check_document(
    document: Mapping[str, object], originals: Iterable[str] = (), exempt: Iterable[str] = ()
) -> list[str]:
    """Write-check problems of one fixture document (empty when it may be written).

    ``originals`` are the replaced abstracts; ``exempt`` strings (kept titles) are masked
    in the body before searching it for 40-character remnants of those abstracts.
    """
    problems: list[str] = []
    response = document.get("response")
    if not isinstance(response, dict) or not isinstance(response.get("body_text"), str):
        return ["response body missing"]
    body_text: str = response["body_text"]
    if len(body_text.encode("utf-8")) > BODY_MAX_BYTES:
        problems.append("body larger than 64 KiB")
    headers = response.get("headers")
    if not isinstance(headers, dict) or not set(headers) <= set(KEPT_HEADERS):
        problems.append("response header outside the allowlist")
    serialized = json.dumps(document, ensure_ascii=False)
    if FORBIDDEN_RE.search(serialized):
        problems.append("credential-like pattern")
    if _EMAIL_AT_RE.search(serialized):
        problems.append("email address")
    if ORCID_RE.search(serialized):
        problems.append("ORCID reference")
    masked = body_text
    for value in sorted((item for item in exempt if item), key=len, reverse=True):
        masked = masked.replace(value, "\x00")
    if any(_remnant(original, masked) for original in originals):
        problems.append("remnant of an original abstract")
    return problems


def serialize(document: Mapping[str, object]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def fixture_path(out_dir: Path, document: Mapping[str, object]) -> Path:
    return out_dir / str(document["provider"]) / f"{document['scenario']}.json"


def _tree_size(out_dir: Path, excluded: set[Path]) -> int:
    if not out_dir.exists():
        return 0
    return sum(
        path.stat().st_size
        for path in out_dir.rglob("*")
        if path.is_file() and path.resolve() not in excluded
    )


def write_documents(
    out_dir: Path,
    prepared: Sequence[tuple[Mapping[str, object], Sanitized]],
    *,
    force: bool,
) -> list[Path]:
    """Check every document, then write all of them; any failure writes nothing."""
    texts: dict[Path, str] = {}
    for document, cleaned in prepared:
        path = fixture_path(out_dir, document)
        problems = check_document(document, cleaned.originals, cleaned.exempt)
        if problems:
            raise RecordingRefused(f"{path.name}: {', '.join(problems)}")
        if path.exists() and not force:
            raise RecordingRefused(f"{path.name} exists; pass --force to overwrite")
        texts[path] = serialize(document)
    new_bytes = sum(len(text.encode("utf-8")) for text in texts.values())
    excluded = {path.resolve() for path in texts}
    if _tree_size(out_dir, excluded) + new_bytes > TOTAL_MAX_BYTES:
        raise RecordingRefused("the fixture tree would exceed 256 KiB")
    for path, text in texts.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return sorted(texts)


# ---------------------------------------------------------------------- recording


def select(names: Iterable[str]) -> tuple[Scenario, ...]:
    by_key = {scenario.key: scenario for scenario in SCENARIOS}
    chosen: list[Scenario] = []
    for name in names:
        scenario = by_key.get(name)
        if scenario is None:
            raise RecordingRefused("unknown scenario")
        if scenario not in chosen:
            chosen.append(scenario)
    return tuple(chosen)


async def capture(
    scenario: Scenario, *, client_factory: ClientFactory, network: NetworkSettings
) -> Exchange:
    """One GET through the bounded client; never follows a redirect."""
    terms = PUBLIC_PROVIDERS[scenario.provider]
    spec = ClientSpec(
        host=urlsplit(scenario.url).hostname or "",
        timeout_s=CAPTURE_TIMEOUT_S,
        max_response_bytes=CAPTURE_MAX_BYTES,
        max_connections=1,
        accept=terms.accept,
    )
    try:
        async with (
            client_factory(spec, network) as client,
            client.stream("GET", scenario.url, params=list(scenario.params)) as response,
        ):
            body = await response.aread()
            return Exchange(response.status_code, tuple(response.headers.items()), body)
    except (httpx2.HTTPError, ResponseTooLarge, UnsupportedEncoding):
        raise RecordingRefused(f"{scenario.key}: request failed") from None


async def record(
    scenarios: Sequence[Scenario],
    *,
    out_dir: Path,
    force: bool,
    client_factory: ClientFactory,
    network: NetworkSettings,
    clock: Clock,
    monotonic: Callable[[], float],
    sleep: Callable[[float], Awaitable[None]],
) -> list[Path]:
    """Capture every scenario politely, sanitize, check, then write all fixtures."""
    prepared: list[tuple[Mapping[str, object], Sanitized]] = []
    last_any: float | None = None
    last_arxiv: float | None = None
    for scenario in scenarios:
        earliest = [] if last_any is None else [last_any + REQUEST_GAP_S]
        if scenario.provider == "arxiv" and last_arxiv is not None:
            earliest.append(last_arxiv + ARXIV_GAP_S)
        delay = max(earliest, default=0.0) - monotonic()
        if delay > 0:
            await sleep(delay)
        exchange = await capture(scenario, client_factory=client_factory, network=network)
        last_any = monotonic()
        if scenario.provider == "arxiv":
            last_arxiv = last_any
        cleaned = sanitize(scenario, exchange)
        document = fixture_document(
            provider=scenario.provider,
            scenario=scenario.name,
            url=scenario.url,
            params=scenario.params,
            status=exchange.status,
            headers=exchange.headers,
            body_text=cleaned.body_text,
            sanitized=cleaned.notes,
            recorded_at=clock.now(),
            synthetic=False,
        )
        prepared.append((document, cleaned))
    return write_documents(out_dir, prepared, force=force)


def run(
    *,
    live: bool,
    scenarios: Sequence[str],
    force: bool,
    out_dir: Path,
    environ: Mapping[str, str],
    client_factory: ClientFactory = default_client_factory,
    network: NetworkSettings | None = None,
    clock: Clock | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    """Exit 0 when written, 1 when a check refused, 2 without ``live`` or under ``CI``."""
    if environ.get("CI"):
        print("refused: the fixture recorder never runs in CI", file=stderr)
        return EXIT_REFUSED
    if not live:
        print("refused: recording sends network requests; pass --live", file=stderr)
        return EXIT_REFUSED
    for name in ("httpx2", "httpcore2", "asyncio"):
        logging.getLogger(name).setLevel(logging.WARNING)
    try:
        chosen = select(scenarios)
        paths = asyncio.run(
            record(
                chosen,
                out_dir=out_dir,
                force=force,
                client_factory=client_factory,
                network=network or NetworkSettings(),
                clock=clock or _UtcClock(),
                monotonic=monotonic,
                sleep=sleep,
            )
        )
    except RecordingRefused as refusal:
        print(f"refused: {refusal}", file=stderr)
        return EXIT_CHECK_FAILED
    for path in paths:
        print(f"wrote {path.parent.name}/{path.name}", file=stdout)
    print("review the diff before committing", file=stdout)
    return 0
