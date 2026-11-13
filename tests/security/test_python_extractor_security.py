"""Negative tests of the Python extractor boundary: no execution, no codec lookup by
untrusted names, bounded work on pathological input, and no source text in results."""

import codecs
import sys
import time
import tokenize
import uuid
import warnings
from pathlib import Path

import pytest

from asca.application.ports import DEFAULT_INDEX_LIMITS, FileExtraction
from asca.domain.provenance import MODULE_QUALIFIED_NAME, FileIssueKind
from asca.infrastructure.indexing.python_symbols import PythonAstExtractor

pytestmark = pytest.mark.security

EXTRACTOR = PythonAstExtractor()


def _extract(data: bytes) -> FileExtraction:
    return EXTRACTOR.extract(data, DEFAULT_INDEX_LIMITS)


def test_indexed_code_is_never_executed(tmp_path: Path) -> None:
    sentinel = tmp_path / "sentinel.txt"
    module_name = "asca_never_imported_" + uuid.uuid4().hex
    source = (
        "import os\n"
        "import sys\n"
        f"import {module_name}\n"
        f"open({str(sentinel)!r}, 'w').write('executed')\n"
        f"os.system('touch {sentinel}')\n"
        "sys.modules['asca_injected'] = sys\n"
        "raise SystemExit(3)\n"
        "def payload():\n"
        f"    open({str(sentinel)!r}, 'w').write('called')\n"
        "class Meta(type):\n"
        "    def __new__(mcs, *args):\n"
        f"        open({str(sentinel)!r}, 'w').write('class')\n"
        "if __name__ == '__main__':\n"
        "    payload()\n"
    ).encode()
    before = set(sys.modules)
    extraction = _extract(source)
    assert extraction.issue is None
    assert {symbol.qualified_name for symbol in extraction.symbols} == {
        MODULE_QUALIFIED_NAME,
        "payload",
        "Meta",
        "Meta.__new__",
    }
    assert not sentinel.exists()
    assert set(sys.modules) == before
    assert module_name not in sys.modules
    assert "asca_injected" not in sys.modules


def test_cookie_names_never_reach_codecs_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    evil = "asca-evil-codec-" + uuid.uuid4().hex[:8]
    looked_up: list[str] = []

    def search(name: str) -> None:
        looked_up.append(name)
        raise AssertionError("a codec search function was consulted")

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("codec lookup is not allowed")

    monkeypatch.setattr(codecs, "lookup", refuse)
    monkeypatch.setattr(tokenize, "detect_encoding", refuse)
    codecs.register(search)
    try:
        results = {
            name: _extract(b"# -*- coding: " + name.encode("ascii") + b" -*-\nx = 1\n").issue
            for name in (evil, "rot13", "unicode_escape", "utf-16", "utf-8", "latin-1", "ascii")
        }
        undecodable = _extract(b"# coding: ascii\nx = '\xe9'\n").issue
    finally:
        codecs.unregister(search)
    assert looked_up == []
    assert results == {
        evil: FileIssueKind.UNSUPPORTED_ENCODING,
        "rot13": FileIssueKind.UNSUPPORTED_ENCODING,
        "unicode_escape": FileIssueKind.UNSUPPORTED_ENCODING,
        "utf-16": FileIssueKind.UNSUPPORTED_ENCODING,
        "utf-8": None,
        "latin-1": None,
        "ascii": None,
    }
    assert undecodable is FileIssueKind.DECODE_ERROR


@pytest.mark.parametrize(
    "source",
    [
        "x = " + "-" * 100_000 + "1\n",
        "x = " + "+".join(["1"] * 100_000) + "\n",
        "x = a" + ".b" * 200_000 + "\n",
        "x = " + "(" * 1000 + "1" + ")" * 1000 + "\n",
        "".join("    " * level + "if x:\n" for level in range(101)) + "    " * 101 + "pass\n",
    ],
    ids=["unary_minus", "binop_terms", "attribute_chain", "parentheses", "indentation"],
)
def test_pathological_nesting_is_too_complex_or_syntax_error_within_2s(source: str) -> None:
    started = time.monotonic()
    extraction = _extract(source.encode("ascii"))
    assert time.monotonic() - started < 2.0
    assert extraction.issue in (FileIssueKind.TOO_COMPLEX, FileIssueKind.SYNTAX_ERROR)
    assert extraction.symbols == ()


def test_result_is_identical_under_warnings_error() -> None:
    source = b"def f():\n    return '\\d' + \"\\q\"\n\nx = 1 is 1\n"
    reference = _extract(source)
    assert reference.issue is None
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        strict = _extract(source)
    assert strict == reference


def test_issue_records_never_contain_source_text() -> None:
    secret = "ASCA_SECRET_" + uuid.uuid4().hex
    sources = [
        f"token = '{secret}' +\n",
        f"def {secret}(:\n",
        f"# coding: {secret}\n",
        f"x = '{secret}'\x00\n",
    ]
    for source in sources:
        extraction = _extract(source.encode("utf-8"))
        assert extraction.issue is not None
        assert extraction.symbols == ()
        assert secret not in repr(extraction)
        assert secret not in str(extraction.issue)
