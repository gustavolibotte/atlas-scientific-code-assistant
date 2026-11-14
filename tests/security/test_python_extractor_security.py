"""Negative tests of the Python extractor boundary: no execution, no codec lookup by
untrusted names, bounded work on pathological input, and no source text in results."""

import codecs
import sys
import time
import tokenize
import uuid
import warnings
from pathlib import Path
from typing import NoReturn

import pytest

from asca.application.ports import DEFAULT_INDEX_LIMITS, FileExtraction
from asca.domain.provenance import MODULE_QUALIFIED_NAME, FileIssueKind
from asca.infrastructure.indexing import python_symbols
from asca.infrastructure.indexing.python_symbols import MAX_AST_DEPTH, PythonAstExtractor

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


def _at_depth(frames: int, data: bytes) -> FileExtraction:
    if frames == 0:
        return _extract(data)
    return _at_depth(frames - 1, data)


def _stack_depth() -> int:
    frame, depth = sys._getframe(), 0
    while frame is not None:
        frame, depth = frame.f_back, depth + 1
    return depth


def _chain(terms: int) -> bytes:
    return ("def f():\n    return " + "+".join(["1"] * terms) + "\n").encode("ascii")


@pytest.mark.parametrize("terms", [700, 900, 990, 1100, 3000])
def test_result_does_not_depend_on_the_callers_stack_depth(terms: int) -> None:
    # On 3.11 the parser's recursion budget used to shrink with the caller's stack.
    data = _chain(terms)
    shallow = _extract(data)
    # Leave only a few dozen frames of the recursion limit to the extractor.
    deep = _at_depth(sys.getrecursionlimit() - _stack_depth() - 60, data)
    assert deep == shallow
    expected = None if terms + 3 <= MAX_AST_DEPTH else FileIssueKind.TOO_COMPLEX
    assert shallow.issue is expected


def test_nesting_deeper_than_the_bound_is_too_complex_on_every_interpreter() -> None:
    # Module, FunctionDef and Return, then terms - 1 nested BinOps and the innermost
    # Constant: the tree is terms + 3 deep.
    fits = MAX_AST_DEPTH - 3
    assert _extract(_chain(fits)).issue is None
    assert _extract(_chain(fits + 1)).issue is FileIssueKind.TOO_COMPLEX
    unary = ("x = " + "-" * (MAX_AST_DEPTH + 10) + "1\n").encode("ascii")
    assert _extract(unary).issue is FileIssueKind.TOO_COMPLEX


@pytest.mark.parametrize("setting", [0, 640, 4300, 100_000])
def test_result_does_not_depend_on_the_int_digit_limit(setting: int) -> None:
    long_literal = b"def f():\n    return " + b"1" * 5000 + b"\n"
    short_literal = b"def f():\n    return " + b"1" * 1000 + b"\n"
    previous = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(setting)
    try:
        long_result = _extract(long_literal)
        short_result = _extract(short_literal)
        assert sys.get_int_max_str_digits() == setting
    finally:
        sys.set_int_max_str_digits(previous)
    assert long_result.issue is FileIssueKind.SYNTAX_ERROR
    assert short_result.issue is None
    assert [item.qualified_name for item in short_result.symbols] == [MODULE_QUALIFIED_NAME, "f"]


def test_result_does_not_depend_on_a_lowered_recursion_limit() -> None:
    data = _chain(900)
    reference = _extract(data)
    assert reference.issue is None
    previous = sys.getrecursionlimit()
    sys.setrecursionlimit(250)
    try:
        lowered = _extract(data)
        assert sys.getrecursionlimit() == 250
    finally:
        sys.setrecursionlimit(previous)
    assert lowered == reference


def test_unexpected_parser_errors_propagate_to_the_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(*args: object, **kwargs: object) -> NoReturn:
        raise LookupError("parser bug")

    monkeypatch.setattr(python_symbols.ast, "parse", broken)
    with pytest.raises(LookupError, match="parser bug"):
        _extract(b"x = 1\n")


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
