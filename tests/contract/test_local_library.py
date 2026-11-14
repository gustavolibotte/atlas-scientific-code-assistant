"""Local curated library adapter over synthetic libraries in ``tmp_path`` (no network)."""

from __future__ import annotations

import asyncio
import os
import shutil
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
from knowledge_contract import assert_provider_contract

from asca.application.demo import FixedClock
from asca.application.knowledge.models import (
    CandidateRef,
    ContentAvailability,
    DocumentKind,
    FetchResult,
    HealthState,
    KnowledgeQuery,
    LicenseInfo,
    LicenseScope,
    PartialDate,
    PidOrigin,
    PidRole,
    ProviderError,
    ProviderErrorKind,
    ProviderHealth,
    ProviderKind,
    SearchResult,
    VersionKind,
)
from asca.application.knowledge.pids import pid_text
from asca.application.knowledge.policy import AuthorityRule, suggest_authority
from asca.domain.provenance import AccessClass, SourceAuthority, sha256_text
from asca.infrastructure.knowledge.local import (
    MANIFEST_MAX_BYTES,
    LocalLibraryProvider,
    ManifestInvalid,
    parse_manifest,
)
from asca.infrastructure.knowledge.settings import LocalLibrarySettings

pytestmark = pytest.mark.contract

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "knowledge" / "local"
NOW = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
EXIT_QUERY = "energy reconstruction liquid argon calorimeter neural network"
HEADER = 'format = "asca-library/1"\n'


def document(path: str, title: str, **extra: str) -> str:
    fields = {
        "path": f'"{path}"',
        "title": f'"{title}"',
        "version": '"2026-11-01"',
        "access_class": '"public"',
        **extra,
    }
    body = "".join(f"{key} = {value}\n" for key, value in fields.items())
    return f"[[documents]]\n{body}"


def library(root: Path, manifest: str, files: dict[str, str | bytes]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.toml").write_text(manifest, encoding="utf-8")
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
    return root


def provider(root: Path, timeout_s: float = 5.0) -> LocalLibraryProvider:
    return LocalLibraryProvider(
        LocalLibrarySettings(True, str(root), timeout_s), clock=FixedClock(NOW)
    )


def search(root: Path, text: str, limit: int = 5) -> SearchResult | ProviderError:
    return asyncio.run(provider(root).search(KnowledgeQuery(text, limit)))


def fixture_library(tmp_path: Path) -> Path:
    root = tmp_path / "library"
    shutil.copytree(FIXTURE, root)
    return root


def test_descriptor() -> None:
    descriptor = provider(FIXTURE).descriptor
    assert descriptor.id == "local"
    assert descriptor.kind is ProviderKind.LOCAL
    assert descriptor.label == "Local curated library"
    assert descriptor.adapter_version == "local/1"
    assert descriptor.access_class is AccessClass.PUBLIC
    assert descriptor.access_conditions is None
    assert descriptor.max_query_access is AccessClass.RESTRICTED
    assert descriptor.uses_network is False
    assert descriptor.supports_fetch is True
    assert descriptor.timeout_s == 5.0


def test_fixture_library_maps_the_internal_note(tmp_path: Path) -> None:
    result = search(fixture_library(tmp_path), EXIT_QUERY)
    assert isinstance(result, SearchResult)
    assert (result.total_reported, result.dropped_items) == (1, 0)
    (candidate,) = result.candidates
    assert candidate.ref == CandidateRef("local", "notes/optimal-filtering.md")
    assert candidate.title.startswith("Synthetic local note on liquid argon")
    assert candidate.version.kind is VersionKind.DECLARED
    assert candidate.version.label == "declared:2026-11-01"
    assert candidate.access_class is AccessClass.INTERNAL
    assert candidate.access_conditions is not None
    assert candidate.declared_authority is SourceAuthority.WORKING_MATERIAL
    assert candidate.content is ContentAvailability.FULL_TEXT
    assert candidate.landing_url is None
    assert candidate.issued == PartialDate(2026, 11)
    assert candidate.authors == ("A. Curator",)
    assert candidate.author_count == 1
    assert candidate.licenses == (LicenseInfo("CC0-1.0", None, LicenseScope.CONTENT),)
    assert candidate.retrieved_at == NOW
    assert [(pid_text(item.pid), item.role, item.origin) for item in candidate.pids] == [
        ("arxiv:2109.05124", PidRole.IDENTITY, PidOrigin.CURATED_LINK),
        ("local_document:notes/optimal-filtering.md", PidRole.RELATED, PidOrigin.NATIVE),
    ]
    assert candidate.snippet is not None
    assert candidate.snippet.startswith("# Synthetic note")
    suggestion = suggest_authority(candidate)
    assert (suggestion.authority, suggestion.rule) == (
        SourceAuthority.WORKING_MATERIAL,
        AuthorityRule.LOCAL_DECLARED,
    )


def test_fetch_returns_the_exact_file_text(tmp_path: Path) -> None:
    root = fixture_library(tmp_path)
    path = root / "notes" / "optimal-filtering.md"
    outcome = asyncio.run(provider(root).fetch(CandidateRef("local", "notes/optimal-filtering.md")))
    assert isinstance(outcome, FetchResult)
    text = path.read_bytes().decode("utf-8")
    assert outcome.document.text == text
    assert outcome.document.text_sha256 == sha256_text(text)
    assert outcome.document.kind is DocumentKind.FULL_TEXT
    assert outcome.document.media_type == "text/markdown; charset=utf-8"
    assert outcome.document.raw_sha256 is None
    assert outcome.document.source_url is None
    assert outcome.document.access_class is AccessClass.INTERNAL
    assert outcome.document.redactions == 0
    assert outcome.candidate.rank == 0
    assert "Optimal filtering minimises the noise variance" in outcome.document.text


def test_fetch_keeps_text_unnormalised(tmp_path: Path) -> None:
    raw = "Line one\r\n\tindented  twice\u00a0spaced\r\n\r\n\r\n\r\nend"
    root = library(
        tmp_path / "lib", HEADER + document("a.txt", "Plain note"), {"a.txt": raw.encode()}
    )
    outcome = asyncio.run(provider(root).fetch(CandidateRef("local", "a.txt")))
    assert isinstance(outcome, FetchResult)
    assert outcome.document.text == raw
    assert outcome.document.media_type == "text/plain; charset=utf-8"


def test_provider_contract(tmp_path: Path) -> None:
    assert_provider_contract(provider(fixture_library(tmp_path)), KnowledgeQuery(EXIT_QUERY))


def test_unlisted_files_are_ignored(tmp_path: Path) -> None:
    root = library(
        tmp_path / "lib",
        HEADER + document("listed.md", "Calorimeter note"),
        {
            "listed.md": "calorimeter",
            "unlisted.md": "calorimeter calorimeter calorimeter",
            "deep/unlisted.txt": "calorimeter",
        },
    )
    result = search(root, "calorimeter")
    assert isinstance(result, SearchResult)
    assert [item.ref.native_id for item in result.candidates] == ["listed.md"]
    assert result.dropped_items == 0


def test_scoring_and_order(tmp_path: Path) -> None:
    manifest = HEADER + "".join(
        [
            document("b-text-only.md", "Plain note"),
            document("a-title.md", "Pulse shapes"),
            document("c-tie.md", "Plain note"),
            document("d-missing-term.md", "Pulse note"),
            document("e-weak.md", "Plain note"),
        ]
    )
    root = library(
        tmp_path / "lib",
        manifest,
        {
            # title "Pulse" scores 3 per occurrence; text occurrences score 1.
            "a-title.md": "one shape here",
            "b-text-only.md": "pulse pulse pulse shape",
            "c-tie.md": "pulse pulse pulse shape",
            "d-missing-term.md": "pulse pulse pulse pulse",
            "e-weak.md": "PULSE Shape",
        },
    )
    result = search(root, "the pulse shape")
    assert isinstance(result, SearchResult)
    ranked = [(item.ref.native_id, item.rank) for item in result.candidates]
    assert ranked == [("a-title.md", 0), ("b-text-only.md", 1), ("c-tie.md", 2), ("e-weak.md", 3)]
    assert result.total_reported == 4
    limited = search(root, "pulse shape", limit=2)
    assert isinstance(limited, SearchResult)
    assert [item.ref.native_id for item in limited.candidates] == ["a-title.md", "b-text-only.md"]
    assert limited.total_reported == 4


def test_empty_query_is_unsupported(tmp_path: Path) -> None:
    outcome = search(fixture_library(tmp_path), "the and of")
    assert outcome == ProviderError(ProviderErrorKind.UNSUPPORTED, "empty_query")


def test_restricted_query_is_answered(tmp_path: Path) -> None:
    root = fixture_library(tmp_path)
    query = KnowledgeQuery(EXIT_QUERY, 5, AccessClass.RESTRICTED)
    outcome = asyncio.run(provider(root).search(query))
    assert isinstance(outcome, SearchResult)
    assert len(outcome.candidates) == 1


def test_unusable_listed_documents_are_dropped(tmp_path: Path) -> None:
    manifest = HEADER + "".join(
        document(name, "Calorimeter note")
        for name in ("good.md", "missing.md", "latin1.md", "nul.md", "empty.md", "link.md")
    )
    root = library(
        tmp_path / "lib",
        manifest,
        {
            "good.md": "calorimeter",
            "latin1.md": "calorimeter café".encode("latin-1"),
            "nul.md": b"calorimeter\x00",
            "empty.md": b"",
        },
    )
    (tmp_path / "outside.md").write_text("calorimeter secret outside the root", encoding="utf-8")
    os.symlink(tmp_path / "outside.md", root / "link.md")
    result = search(root, "calorimeter")
    assert isinstance(result, SearchResult)
    assert [item.ref.native_id for item in result.candidates] == ["good.md"]
    assert result.dropped_items == 5
    for name in ("missing.md", "latin1.md", "nul.md", "empty.md", "link.md"):
        outcome = asyncio.run(provider(root).fetch(CandidateRef("local", name)))
        assert outcome == ProviderError(ProviderErrorKind.NOT_FOUND, "not_found")


def test_oversized_document_is_dropped(tmp_path: Path) -> None:
    root = library(
        tmp_path / "lib",
        HEADER + document("big.txt", "Big calorimeter note"),
        {"big.txt": b"a" * (2_097_152 + 1)},
    )
    result = search(root, "calorimeter")
    assert isinstance(result, SearchResult)
    assert (result.candidates, result.dropped_items) == ((), 1)


@pytest.mark.parametrize(
    ("ref", "code"),
    [
        (CandidateRef("inspire", "notes/optimal-filtering.md"), "invalid_native_id"),
        (CandidateRef("local", "/etc/passwd"), "invalid_native_id"),
        (CandidateRef("local", "../outside.md"), "invalid_native_id"),
        (CandidateRef("local", "manifest.toml"), "invalid_native_id"),
        (CandidateRef("local", "notes/unlisted.md"), "not_found"),
    ],
)
def test_fetch_refusals(tmp_path: Path, ref: CandidateRef, code: str) -> None:
    outcome = asyncio.run(provider(fixture_library(tmp_path)).fetch(ref))
    assert isinstance(outcome, ProviderError)
    assert outcome.code == code
    if code == "invalid_native_id":
        assert outcome.kind is ProviderErrorKind.UNSUPPORTED


def test_missing_manifest_is_not_configured(tmp_path: Path) -> None:
    root = tmp_path / "lib"
    root.mkdir()
    (root / "note.md").write_text("calorimeter", encoding="utf-8")
    expected = ProviderError(ProviderErrorKind.NOT_CONFIGURED, "manifest_missing")
    assert search(root, "calorimeter") == expected
    fetched = asyncio.run(provider(root).fetch(CandidateRef("local", "note.md")))
    assert fetched == expected
    health = asyncio.run(provider(root).health())
    assert (health.state, health.error) == (HealthState.MISCONFIGURED, expected)


def test_symlinked_manifest_is_invalid(tmp_path: Path) -> None:
    root = tmp_path / "lib"
    root.mkdir()
    (tmp_path / "real.toml").write_text(HEADER, encoding="utf-8")
    os.symlink(tmp_path / "real.toml", root / "manifest.toml")
    outcome = search(root, "calorimeter")
    assert outcome == ProviderError(ProviderErrorKind.NOT_CONFIGURED, "manifest_invalid")


def test_invalid_manifest_is_not_configured(tmp_path: Path) -> None:
    root = library(tmp_path / "lib", HEADER + "unexpected = 1\n", {})
    outcome = search(root, "calorimeter")
    assert outcome == ProviderError(ProviderErrorKind.NOT_CONFIGURED, "manifest_invalid")
    health = asyncio.run(provider(root).health())
    assert health.state is HealthState.MISCONFIGURED


def test_unreadable_root_is_not_configured(tmp_path: Path) -> None:
    expected = ProviderError(ProviderErrorKind.NOT_CONFIGURED, "library_unreadable")
    assert search(tmp_path / "absent", "calorimeter") == expected


def test_too_many_files_is_unreadable(tmp_path: Path) -> None:
    root = library(tmp_path / "lib", HEADER, {})
    for index in range(1001):
        (root / f"n{index:04d}.txt").write_bytes(b"x")
    expected = ProviderError(ProviderErrorKind.NOT_CONFIGURED, "library_unreadable")
    assert search(root, "calorimeter") == expected


def test_health_available(tmp_path: Path) -> None:
    health = asyncio.run(provider(fixture_library(tmp_path)).health(deep=True))
    assert (health.provider_id, health.state, health.error) == (
        "local",
        HealthState.AVAILABLE,
        None,
    )


def test_slow_library_times_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = fixture_library(tmp_path)
    releases = [threading.Event(), threading.Event()]
    pending = iter(releases)
    slow = provider(root, timeout_s=1.0)

    def blocked() -> object:
        next(pending).wait(10)
        return ProviderError(ProviderErrorKind.NOT_CONFIGURED, "library_unreadable")

    monkeypatch.setattr(slow, "_load_sync", blocked, raising=False)

    async def run() -> tuple[object, object]:
        try:
            outcome = await slow.search(KnowledgeQuery(EXIT_QUERY))
            releases[0].set()
            health = await slow.health()
            return outcome, health
        finally:
            for release in releases:
                release.set()

    outcome, health = asyncio.run(run())
    assert outcome == ProviderError(ProviderErrorKind.TIMEOUT, "provider_timeout")
    assert isinstance(health, ProviderHealth)
    assert health.state is HealthState.UNAVAILABLE


def test_published_hint_and_report_numbers(tmp_path: Path) -> None:
    manifest = HEADER + document(
        "paper.md",
        "Published calorimeter paper",
        authority_hint='"published"',
        pids=(
            '["doi:10.5555/ASCA-TEST.1", "cds_report:ATLAS-CONF-2026-001",'
            ' "cds_report:LHCB-PAPER-2026-001", "inspire:1"]'
        ),
    )
    root = library(tmp_path / "lib", manifest, {"paper.md": "calorimeter"})
    result = search(root, "calorimeter")
    assert isinstance(result, SearchResult)
    (candidate,) = result.candidates
    roles = {pid_text(item.pid): item.role for item in candidate.pids}
    assert roles == {
        "doi:10.5555/asca-test.1": PidRole.IDENTITY,
        "inspire:1": PidRole.IDENTITY,
        "cds_report:ATLAS-CONF-2026-001": PidRole.IDENTITY,
        "cds_report:LHCB-PAPER-2026-001": PidRole.RELATED,
        "local_document:paper.md": PidRole.RELATED,
    }
    assert candidate.declared_authority is SourceAuthority.PUBLISHED
    assert suggest_authority(candidate).authority is SourceAuthority.PUBLISHED


def test_automated_hint(tmp_path: Path) -> None:
    manifest = HEADER + document(
        "auto.md", "Generated calorimeter summary", authority_hint='"automated_inference"'
    )
    root = library(tmp_path / "lib", manifest, {"auto.md": "calorimeter"})
    result = search(root, "calorimeter")
    assert isinstance(result, SearchResult)
    (candidate,) = result.candidates
    assert candidate.declared_authority is SourceAuthority.AUTOMATED_INFERENCE
    assert candidate.authors == ()
    assert candidate.author_count is None
    assert candidate.licenses == ()
    assert suggest_authority(candidate).authority is SourceAuthority.AUTOMATED_INFERENCE


# ---------------------------------------------------------------------- manifest validation


def manifest_bytes(*documents: str, header: str = HEADER) -> bytes:
    return (header + "".join(documents)).encode("utf-8")


def test_minimal_manifest_parses() -> None:
    (entry,) = parse_manifest(manifest_bytes(document("a.md", "A note")))
    assert entry.path == "a.md"
    assert entry.authority is SourceAuthority.WORKING_MATERIAL
    assert entry.access_class is AccessClass.PUBLIC
    assert parse_manifest(manifest_bytes()) == ()


INVALID_MANIFESTS = {
    "extra key": manifest_bytes(document("a.md", "A", unexpected='"x"')),
    "missing access_class": manifest_bytes(
        '[[documents]]\npath = "a.md"\ntitle = "A"\nversion = "1"\n'
    ),
    "duplicate path": manifest_bytes(document("a.md", "A"), document("a.md", "B")),
    "bad suffix": manifest_bytes(document("a.toml", "A")),
    "pdf suffix": manifest_bytes(document("a.pdf", "A")),
    "absolute path": manifest_bytes(document("/etc/a.md", "A")),
    "parent path": manifest_bytes(document("../a.md", "A")),
    "whitespace path": manifest_bytes(document("my note.md", "A")),
    "wrong format": manifest_bytes(document("a.md", "A"), header='format = "asca-library/2"\n'),
    "missing format": manifest_bytes(document("a.md", "A"), header=""),
    "public with conditions": manifest_bytes(
        document("a.md", "A", access_conditions='"Members only"')
    ),
    "internal without conditions": manifest_bytes(document("a.md", "A", access_class='"internal"')),
    "control in conditions": manifest_bytes(
        document("a.md", "A", access_class='"internal"', access_conditions='"x\\u0000y"')
    ),
    "unknown access class": manifest_bytes(document("a.md", "A", access_class='"secret"')),
    "published ceiling not a hint": manifest_bytes(
        document("a.md", "A", authority_hint='"approved_internal"')
    ),
    "bad pid": manifest_bytes(document("a.md", "A", pids='["url:https://example.org"]')),
    "duplicate pid": manifest_bytes(
        document("a.md", "A", pids='["arxiv:2109.05124", "arXiv:2109.05124v2"]')
    ),
    "two arxiv identities": manifest_bytes(
        document("a.md", "A", pids='["arxiv:2109.05124", "arxiv:2111.08590"]')
    ),
    "too many pids": manifest_bytes(
        document("a.md", "A", pids="[" + ", ".join(f'"inspire:{n}"' for n in range(1, 10)) + "]")
    ),
    "bad issued": manifest_bytes(document("a.md", "A", issued='"November 2026"')),
    "control in title": manifest_bytes(document("a.md", "A\\u001b[31m")),
    "padded title": manifest_bytes(document("a.md", " A")),
    "blank version": manifest_bytes(document("a.md", "A", version='" "')),
    "bidi in license": manifest_bytes(document("a.md", "A", license='"CC\\u202eBY"')),
    "control in author": manifest_bytes(document("a.md", "A", authors='["A\\u0007"]')),
    "too many authors": manifest_bytes(
        document("a.md", "A", authors='["a", "b", "c", "d", "e", "f"]')
    ),
    "non-string title": manifest_bytes(
        '[[documents]]\npath = "a.md"\ntitle = 3\nversion = "1"\naccess_class = "public"\n'
    ),
    "toml syntax": b'format = "asca-library/1"\n[[documents]\n',
    "not utf-8": b'format = "asca-library/1"\n# \xff\n',
    "too many documents": manifest_bytes(*(document(f"n{index}.md", "N") for index in range(501))),
}


@pytest.mark.parametrize("name", sorted(INVALID_MANIFESTS))
def test_invalid_manifests_are_refused(name: str) -> None:
    with pytest.raises(ManifestInvalid) as raised:
        parse_manifest(INVALID_MANIFESTS[name])
    assert str(raised.value) == "manifest_invalid"
    assert raised.value.__cause__ is None


def test_oversized_manifest_is_refused() -> None:
    data = manifest_bytes(document("a.md", "A")) + b"#" * MANIFEST_MAX_BYTES
    with pytest.raises(ManifestInvalid):
        parse_manifest(data)


def test_manifest_errors_never_echo_values() -> None:
    canary = "canary-value-7f3a"
    data = manifest_bytes(document("a.md", "A", unexpected=f'"{canary}"'))
    with pytest.raises(ManifestInvalid) as raised:
        parse_manifest(data)
    assert canary not in repr(raised.value)
    assert raised.value.__suppress_context__
