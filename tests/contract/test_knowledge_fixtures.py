"""Committed knowledge fixtures, the recorder's sanitizers and its write checks."""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx2
import pytest
from defusedxml.ElementTree import fromstring
from http_replay import ReplayTransport, fixture_from_mapping, load_fixture, replay_factory
from hypothesis import given, settings
from hypothesis import strategies as st
from knowledge_adapters import CLOCK, FIXTURES, FakeTime

from asca.infrastructure.knowledge import recording
from asca.infrastructure.knowledge.http import USER_AGENT
from asca.infrastructure.knowledge.recording import (
    BODY_MAX_BYTES,
    CHALLENGE_BODY,
    PUBLIC_PROVIDERS,
    SCENARIO_NAMES,
    SCENARIOS,
    TOTAL_MAX_BYTES,
    Exchange,
    RecordingRefused,
    Sanitized,
    check_document,
    fixture_document,
    kept_headers,
    sanitize,
    sanitize_arxiv,
    sanitize_inspire,
    write_documents,
)

pytestmark = pytest.mark.contract

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "record_knowledge_fixtures.py"
JSON_FIXTURES = sorted(FIXTURES.rglob("*.json"))
SYNTHETIC_SENTENCE = "Optimal filtering minimises the noise variance of the amplitude estimate."
REQUIRED = {
    "format",
    "provider",
    "scenario",
    "synthetic",
    "recorded_at",
    "recorder",
    "metadata_license",
    "terms_url",
    "sanitized",
    "request",
    "response",
}
COMMITTED = {
    "inspire/lar_nn_search.json": False,
    "inspire/fetch_1920956.json": False,
    "arxiv/lar_nn_search.json": False,
    "arxiv/fetch_2109.05124v2.json": False,
    "arxiv/fetch_unknown.json": False,
    "hepdata/lar_nn_search_blocked.json": False,
    "inspire/rate_limited_429.json": True,
    "arxiv/unavailable_503.json": True,
    "arxiv/error_entry.json": True,
    "hepdata/synthetic_search.json": True,
    "hostile/inspire_hostile_title.json": True,
    "hostile/arxiv_dtd_bomb.json": True,
    "hostile/arxiv_xxe.json": True,
    "hostile/json_duplicate_keys.json": True,
    "hostile/json_nan.json": True,
}
AT = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


def load(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def rel(path: Path) -> str:
    return path.relative_to(FIXTURES).as_posix()


# ---------------------------------------------------------------------- committed fixtures


def test_the_committed_fixture_set_is_complete_and_flagged() -> None:
    present = {rel(path): load(path)["synthetic"] for path in JSON_FIXTURES}
    for name, synthetic in COMMITTED.items():
        assert present.get(name) is synthetic, name


@pytest.mark.parametrize("path", JSON_FIXTURES, ids=rel)
def test_every_fixture_is_well_formed_and_licence_clean(path: Path) -> None:
    data = load(path)
    assert set(data) == REQUIRED
    assert data["format"] == "asca-http-fixture/1"
    assert isinstance(data["synthetic"], bool)
    terms = PUBLIC_PROVIDERS[data["provider"]]
    assert data["metadata_license"] == terms.metadata_license
    assert data["terms_url"] == terms.terms_url
    assert data["request"]["url"] == terms.base_url
    assert data["request"]["method"] == "GET"
    params = [tuple(pair) for pair in data["request"]["params"]]
    assert params == sorted(params)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", data["recorded_at"])
    expected_recorder = "asca-synthetic/1" if data["synthetic"] else "asca-recorder/1"
    assert data["recorder"] == expected_recorder
    if not data["synthetic"]:
        assert data["sanitized"], "a real recording lists its sanitizers"
    assert check_document(data) == []
    fixture = load_fixture(path)  # verifies body_sha256 and the header allowlist
    assert len(fixture.body_text.encode("utf-8")) <= BODY_MAX_BYTES
    assert "set-cookie" not in dict(fixture.headers)


def test_the_fixture_tree_stays_small() -> None:
    total = sum(path.stat().st_size for path in FIXTURES.rglob("*") if path.is_file())
    assert total <= TOTAL_MAX_BYTES


def test_recorded_fixtures_carry_no_original_abstracts_and_at_most_three_authors() -> None:
    for name in ("inspire/lar_nn_search.json", "inspire/fetch_1920956.json"):
        body = json.loads(load_fixture(FIXTURES / name).body_text)
        for hit in body["hits"]["hits"]:
            for abstract in hit["metadata"].get("abstracts", []):
                assert abstract["value"].endswith(SYNTHETIC_SENTENCE)
    for name in ("arxiv/lar_nn_search.json", "arxiv/fetch_2109.05124v2.json"):
        root = fromstring(load_fixture(FIXTURES / name).body_text.encode("utf-8"))
        entries = root.findall("{http://www.w3.org/2005/Atom}entry")
        assert entries
        for entry in entries:
            summary = entry.findtext("{http://www.w3.org/2005/Atom}summary") or ""
            assert summary.endswith(SYNTHETIC_SENTENCE)
            assert len(entry.findall("{http://www.w3.org/2005/Atom}author")) <= 3
            assert entry.find("{http://arxiv.org/schemas/atom}comment") is None
    blocked = load_fixture(FIXTURES / "hepdata/lar_nn_search_blocked.json")
    assert blocked.status == 403 and blocked.body_text == CHALLENGE_BODY
    assert dict(blocked.headers)["cf-mitigated"] == "challenge"


def test_recorded_requests_match_the_scenario_table() -> None:
    for scenario in SCENARIOS:
        fixture = load_fixture(FIXTURES / scenario.provider / f"{scenario.name}.json")
        assert fixture.key == ("GET", scenario.url, tuple(sorted(scenario.params)))


# ---------------------------------------------------------------------- sanitizers


def test_inspire_sanitizer_replaces_abstracts_and_truncates_authors() -> None:
    body = {
        "hits": {
            "total": 1,
            "hits": [
                {
                    "metadata": {
                        "control_number": 9999901,
                        "titles": [{"title": "Synthetic title"}],
                        "abstracts": [{"value": "Original abstract " * 5}, {"source": "x"}],
                        "authors": [{"full_name": f"Author {n}"} for n in range(6)],
                    }
                },
                "not an object",
                {"metadata": "not an object"},
            ],
        },
        "links": {"authors": ["a", "b", "c", "d"]},
    }
    cleaned = sanitize_inspire(json.dumps(body).encode("utf-8"))
    assert "Original abstract" not in cleaned.body_text
    assert cleaned.originals == ("Original abstract " * 5,)
    assert cleaned.exempt == ("Synthetic title",)
    result = json.loads(cleaned.body_text)
    metadata = result["hits"]["hits"][0]["metadata"]
    assert metadata["abstracts"][0]["value"] == recording.SYNTHETIC_ABSTRACT.format(record=9999901)
    assert len(metadata["authors"]) == 3 and len(result["links"]["authors"]) == 3
    assert cleaned.body_text == json.dumps(
        result, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def test_inspire_sanitizer_refuses_non_objects() -> None:
    with pytest.raises(RecordingRefused):
        sanitize_inspire(b"[1, 2]")
    with pytest.raises(RecordingRefused):
        sanitize_inspire(b"{bad json")


def test_arxiv_sanitizer_replaces_summaries_and_drops_personal_data() -> None:
    authors = "".join(
        f"<author><name>Author {n}</name><arxiv:affiliation>Lab {n}</arxiv:affiliation></author>"
        for n in range(5)
    )
    body = (
        '<feed xmlns="http://www.w3.org/2005/Atom" xmlns:arxiv="http://arxiv.org/schemas/atom">'
        "<entry><id>http://arxiv.org/abs/2511.99901v1</id><title>Synthetic title</title>"
        "<summary>Original summary text that must not survive.</summary>"
        f"<arxiv:comment>contact someone</arxiv:comment>{authors}</entry></feed>"
    ).encode()
    cleaned = sanitize_arxiv(body)
    assert "Original summary" not in cleaned.body_text
    assert "Lab " not in cleaned.body_text and "contact" not in cleaned.body_text
    assert cleaned.originals == ("Original summary text that must not survive.",)
    assert cleaned.exempt == ("Synthetic title",)
    root = fromstring(cleaned.body_text.encode("utf-8"))
    entry = root.find("{http://www.w3.org/2005/Atom}entry")
    assert entry is not None
    assert len(entry.findall("{http://www.w3.org/2005/Atom}author")) == 3
    summary = entry.findtext("{http://www.w3.org/2005/Atom}summary")
    assert summary == recording.SYNTHETIC_ABSTRACT.format(record="2511.99901v1")
    assert cleaned.body_text.startswith('<feed xmlns="http://www.w3.org/2005/Atom"')


@pytest.mark.parametrize(
    "body",
    [
        b'<!DOCTYPE feed [<!ENTITY a "b">]><feed/>',
        b"<feed",
        b'<?xml version="1.0"?><!ENTITY x "y"><feed/>',
    ],
)
def test_arxiv_sanitizer_refuses_dtds_and_malformed_xml(body: bytes) -> None:
    with pytest.raises(RecordingRefused):
        sanitize_arxiv(body)


def test_sanitize_dispatch_and_refusals() -> None:
    by_key = {scenario.key: scenario for scenario in SCENARIOS}
    blocked = by_key["hepdata/lar_nn_search_blocked"]
    challenge = Exchange(403, (("CF-Mitigated", "challenge"),), b"<html>secret page</html>")
    assert sanitize(blocked, challenge) == Sanitized(
        CHALLENGE_BODY, ("challenge body replaced",), ()
    )
    with pytest.raises(RecordingRefused, match="challenge"):
        sanitize(blocked, Exchange(200, (), b"{}"))
    inspire_scenario = by_key["inspire/lar_nn_search"]
    with pytest.raises(RecordingRefused, match="challenge"):
        sanitize(inspire_scenario, challenge)
    with pytest.raises(RecordingRefused, match="HTTP status 429"):
        sanitize(inspire_scenario, Exchange(429, (), b"{}"))
    synthetic_blocked = recording.Scenario(
        "hepdata", "success", blocked.url, blocked.params, expect_challenge=False
    )
    with pytest.raises(RecordingRefused, match="no sanitizer"):
        sanitize(synthetic_blocked, Exchange(200, (), b"{}"))


def test_kept_headers_allowlist_and_location_query() -> None:
    kept = kept_headers(
        [
            ("Content-Type", "application/json"),
            ("Set-Cookie", "session=abc"),
            ("Location", "https://example.org/next?token=abc#frag"),
            ("content-type", "text/html"),
            ("Server", "x"),
            ("Retry-After", "5"),
        ]
    )
    assert kept == (
        ("content-type", "application/json"),
        ("location", "https://example.org/next"),
        ("retry-after", "5"),
    )


# ---------------------------------------------------------------------- write checks


def document(body_text: str = "{}", headers: dict[str, str] | None = None) -> dict[str, object]:
    return fixture_document(
        provider="inspire",
        scenario="unit",
        url=PUBLIC_PROVIDERS["inspire"].base_url,
        params=[("q", "x")],
        status=200,
        headers=(headers or {"content-type": "application/json"}).items(),
        body_text=body_text,
        sanitized=(),
        recorded_at=AT,
        synthetic=True,
    )


@pytest.mark.parametrize(
    ("body", "problem"),
    [
        ("x" * (BODY_MAX_BYTES + 1), "body larger than 64 KiB"),
        ('{"h": "Authorization: x"}', "credential-like pattern"),
        ('{"h": "Bearer abcdef"}', "credential-like pattern"),
        ('{"h": "set-cookie"}', "credential-like pattern"),
        ('{"t": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.x"}', "credential-like pattern"),
        ('{"e": "someone@example.org"}', "email address"),
        ('{"o": "ORCID 0000-0000"}', "ORCID reference"),
    ],
)
def test_check_document_refusals(body: str, problem: str) -> None:
    assert problem in check_document(document(body))


def test_check_document_header_allowlist_and_missing_body() -> None:
    bad = document()
    bad["response"]["headers"]["server"] = "x"  # type: ignore[index]
    assert check_document(bad) == ["response header outside the allowlist"]
    assert check_document({"response": {}}) == ["response body missing"]


def test_remnant_check_masks_exempt_titles() -> None:
    abstract = (
        "This abstract repeats a long title phrase verbatim and adds more original words, "
        "followed by a second sentence that only the abstract contains."
    )
    title = "repeats a long title phrase verbatim and adds"
    body = json.dumps({"title": title, "abstract": "Synthetic replacement."})
    assert check_document(document(body), [abstract]) == ["remnant of an original abstract"]
    assert check_document(document(body), [abstract], [title]) == []
    leaked = json.dumps({"abstract": abstract})
    assert check_document(document(leaked), [abstract], [title]) == [
        "remnant of an original abstract"
    ]
    assert check_document(document(body), ["short"]) == []


def test_fixture_document_refuses_non_public_providers() -> None:
    with pytest.raises(RecordingRefused):
        fixture_document(
            provider="local",
            scenario="x",
            url="https://example.org",
            params=(),
            status=200,
            headers=(),
            body_text="",
            sanitized=(),
            recorded_at=AT,
            synthetic=True,
        )


def test_write_documents_checks_everything_before_writing(tmp_path: Path) -> None:
    good = document('{"ok": 1}')
    written = write_documents(tmp_path, [(good, Sanitized("", (), ()))], force=False)
    assert written == [tmp_path / "inspire" / "unit.json"]
    assert fixture_from_mapping(load(written[0])).body_text == '{"ok": 1}'
    with pytest.raises(RecordingRefused, match="exists"):
        write_documents(tmp_path, [(good, Sanitized("", (), ()))], force=False)
    changed = document('{"ok": 2}')
    write_documents(tmp_path, [(changed, Sanitized("", (), ()))], force=True)
    assert load(written[0])["response"]["body_text"] == '{"ok": 2}'

    other = dict(document('{"ok": 3}'), scenario="other")
    leaking = dict(document('{"e": "a@b.org"}'), scenario="leaking")
    with pytest.raises(RecordingRefused, match="email"):
        write_documents(
            tmp_path,
            [(other, Sanitized("", (), ())), (leaking, Sanitized("", (), ()))],
            force=False,
        )
    assert not (tmp_path / "inspire" / "other.json").exists(), "nothing is written on refusal"


def test_write_documents_refuses_a_tree_over_256_kib(tmp_path: Path) -> None:
    (tmp_path / "local").mkdir()
    (tmp_path / "local" / "big.bin").write_bytes(b"x" * (TOTAL_MAX_BYTES - 100))
    with pytest.raises(RecordingRefused, match="256 KiB"):
        write_documents(tmp_path, [(document("{}"), Sanitized("", (), ()))], force=False)
    assert recording._tree_size(tmp_path / "missing", set()) == 0


# ---------------------------------------------------------------------- recording through replay


def committed_replay() -> ReplayTransport:
    return ReplayTransport(
        load_fixture(FIXTURES / scenario.provider / f"{scenario.name}.json")
        for scenario in SCENARIOS
    )


def test_run_records_every_scenario_politely_through_an_injected_factory(tmp_path: Path) -> None:
    replay = committed_replay()
    time = FakeTime()
    stdout, stderr = io.StringIO(), io.StringIO()
    code = recording.run(
        live=True,
        scenarios=SCENARIO_NAMES,
        force=False,
        out_dir=tmp_path,
        environ={},
        client_factory=replay_factory(replay),
        clock=CLOCK,
        monotonic=time.monotonic,
        sleep=time.sleep,
        stdout=stdout,
        stderr=stderr,
    )
    assert (code, stderr.getvalue()) == (0, "")
    replay.assert_all_used()
    assert time.sleeps == [
        pytest.approx(1.0),
        pytest.approx(1.0),
        pytest.approx(3.0),
        pytest.approx(3.0),
        pytest.approx(1.0),
    ]
    for request in replay.requests:
        assert request.headers["User-Agent"] == USER_AGENT
        assert "cookie" not in request.headers and "authorization" not in request.headers
    for scenario in SCENARIOS:
        name = f"{scenario.provider}/{scenario.name}.json"
        fresh, committed = load(tmp_path / name), load(FIXTURES / name)
        assert fresh["recorded_at"] == "2026-11-14T10:00:00Z"
        assert fresh["response"] == committed["response"], "sanitizing is idempotent"
        assert fresh["request"] == committed["request"]
    assert "review the diff" in stdout.getvalue()


def test_run_refuses_without_live_or_in_ci(tmp_path: Path) -> None:
    replay = committed_replay()
    for live, environ in ((False, {}), (True, {"CI": "true"})):
        stderr = io.StringIO()
        code = recording.run(
            live=live,
            scenarios=SCENARIO_NAMES,
            force=False,
            out_dir=tmp_path,
            environ=environ,
            client_factory=replay_factory(replay),
            stderr=stderr,
        )
        assert code == 2 and stderr.getvalue().startswith("refused:")
    assert replay.requests == [] and not any(tmp_path.iterdir())


def test_run_reports_refusals_without_writing(tmp_path: Path) -> None:
    def failing(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("secret-canary", request=request)

    stderr = io.StringIO()
    code = recording.run(
        live=True,
        scenarios=["inspire/fetch_1920956"],
        force=False,
        out_dir=tmp_path,
        environ={},
        client_factory=replay_factory(httpx2.MockTransport(failing)),
        clock=CLOCK,
        stderr=stderr,
    )
    assert code == 1
    assert "request failed" in stderr.getvalue() and "secret-canary" not in stderr.getvalue()
    stderr = io.StringIO()
    unknown = recording.run(
        live=True,
        scenarios=["mcp:chatlas/search"],
        force=False,
        out_dir=tmp_path,
        environ={},
        stderr=stderr,
    )
    assert unknown == 1 and "unknown scenario" in stderr.getvalue()
    assert not any(tmp_path.iterdir())


def test_select_deduplicates_scenarios() -> None:
    chosen = recording.select(["arxiv/fetch_unknown", "arxiv/fetch_unknown"])
    assert [scenario.key for scenario in chosen] == ["arxiv/fetch_unknown"]


def test_script_refuses_without_live() -> None:
    environment = {key: value for key, value in os.environ.items() if key != "CI"}
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=ROOT,
        env={**environment, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 2
    assert "--live" in result.stderr
    help_result = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        cwd=ROOT,
        env={**environment, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert help_result.returncode == 0 and "--scenario" in help_result.stdout


@settings(max_examples=300, deadline=None)
@given(st.text(alphabet="ab9_.+-@ x\n", max_size=40))
def test_linear_email_check_matches_the_documented_pattern(text: str) -> None:
    linear = recording._EMAIL_AT_RE.search(text) is not None
    assert linear == (recording.EMAIL_RE.search(text) is not None)
