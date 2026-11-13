"""Python symbol extraction: kinds, names, spans, duplicates, limits and decoding."""

import ast
import io
import tokenize

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from asca.application.ports import DEFAULT_INDEX_LIMITS, FileExtraction, IndexLimits
from asca.domain.provenance import (
    MODULE_QUALIFIED_NAME,
    FileIssueKind,
    FingerprintAlgorithm,
    Language,
    SourceSpan,
    SymbolKind,
)
from asca.infrastructure.indexing.python_symbols import PythonAstExtractor, decode_source

pytestmark = pytest.mark.unit

EXTRACTOR = PythonAstExtractor()


def extract(source: str | bytes, limits: IndexLimits = DEFAULT_INDEX_LIMITS) -> FileExtraction:
    data = source.encode("utf-8") if isinstance(source, str) else source
    return EXTRACTOR.extract(data, limits)


def kinds(source: str | bytes) -> dict[str, SymbolKind]:
    extraction = extract(source)
    assert extraction.issue is None, extraction.issue
    return {symbol.qualified_name: symbol.kind for symbol in extraction.symbols}


def spans(source: str | bytes) -> dict[str, tuple[int, int]]:
    extraction = extract(source)
    assert extraction.issue is None, extraction.issue
    return {
        symbol.qualified_name: (symbol.span.start_line, symbol.span.end_line)
        for symbol in extraction.symbols
    }


def issue(source: str | bytes, limits: IndexLimits = DEFAULT_INDEX_LIMITS) -> FileIssueKind | None:
    extraction = extract(source, limits)
    if extraction.issue is not None:
        assert extraction.symbols == ()
    return extraction.issue


def test_extractor_identity() -> None:
    assert EXTRACTOR.language is Language.PYTHON
    assert EXTRACTOR.algorithm is FingerprintAlgorithm.PYTHON_AST_1
    assert EXTRACTOR.suffixes == frozenset({".py"})


def test_kinds_and_qualified_names() -> None:
    source = (
        "def f():\n"
        "    pass\n"
        "async def af():\n"
        "    pass\n"
        "class C:\n"
        "    def m(self):\n"
        "        pass\n"
        "    async def am(self):\n"
        "        pass\n"
        "    @staticmethod\n"
        "    def s():\n"
        "        pass\n"
        "    @classmethod\n"
        "    def c(cls):\n"
        "        pass\n"
        "    class Inner:\n"
        "        def deep(self):\n"
        "            pass\n"
    )
    assert kinds(source) == {
        MODULE_QUALIFIED_NAME: SymbolKind.MODULE,
        "f": SymbolKind.FUNCTION,
        "af": SymbolKind.FUNCTION,
        "C": SymbolKind.CLASS,
        "C.m": SymbolKind.METHOD,
        "C.am": SymbolKind.METHOD,
        "C.s": SymbolKind.METHOD,
        "C.c": SymbolKind.METHOD,
        "C.Inner": SymbolKind.CLASS,
        "C.Inner.deep": SymbolKind.METHOD,
    }
    extraction = extract(source)
    names = [symbol.qualified_name for symbol in extraction.symbols]
    assert names == sorted(names)
    assert extraction.skipped_definitions == 0


def test_conditional_definitions_are_symbols() -> None:
    source = (
        "if A:\n    def in_if(): pass\nelse:\n    def in_else(): pass\n"
        "try:\n    def in_try(): pass\n"
        "except ValueError:\n    def in_except(): pass\n"
        "else:\n    def in_try_else(): pass\n"
        "finally:\n    def in_finally(): pass\n"
        "with ctx:\n    def in_with(): pass\n"
        "for x in y:\n    def in_for(): pass\nelse:\n    def in_for_else(): pass\n"
        "while z:\n    def in_while(): pass\n"
        "match v:\n    case 1:\n        def in_match(): pass\n"
        "class C:\n    if A:\n        def m(self): pass\n"
        "async def outer():\n    pass\n"
    )
    names = set(kinds(source))
    assert names == {
        MODULE_QUALIFIED_NAME,
        "in_if",
        "in_else",
        "in_try",
        "in_except",
        "in_try_else",
        "in_finally",
        "in_with",
        "in_for",
        "in_for_else",
        "in_while",
        "in_match",
        "C",
        "C.m",
        "outer",
    }


def test_async_compound_and_try_star_blocks_are_transparent() -> None:
    source = (
        "async def outer():\n"
        "    pass\n"
        "try:\n"
        "    def in_try(): pass\n"
        "except* ValueError:\n"
        "    def in_star(): pass\n"
    )
    assert {"in_try", "in_star", "outer"} <= set(kinds(source))


def test_defs_inside_functions_and_lambdas_are_not_symbols() -> None:
    source = (
        "def outer():\n"
        "    def inner():\n"
        "        pass\n"
        "    class Local:\n"
        "        def m(self): pass\n"
        "    return inner\n"
        "square = lambda x: x * x\n"
        "values = [y for y in range(3)]\n"
        "CONSTANT = 1\n"
        "class C:\n"
        "    def m(self):\n"
        "        def helper(): pass\n"
        "        return helper\n"
        "    attribute = 2\n"
    )
    assert set(kinds(source)) == {MODULE_QUALIFIED_NAME, "outer", "C", "C.m"}


def test_duplicates_merge() -> None:
    source = (
        "class C:\n"  # 1
        "    @property\n"  # 2
        "    def value(self):\n"  # 3
        "        return 1\n"  # 4
        "    @value.setter\n"  # 5
        "    def value(self, v):\n"  # 6
        "        pass\n"  # 7
        "from typing import overload\n"  # 8
        "@overload\n"  # 9
        "def f(x: int) -> int: ...\n"  # 10
        "@overload\n"  # 11
        "def f(x: str) -> str: ...\n"  # 12
        "def f(x):\n"  # 13
        "    return x\n"  # 14
        "if A:\n"  # 15
        "    def g(): pass\n"  # 16
        "else:\n"  # 17
        "    def g(): return 1\n"  # 18
        "def h(): pass\n"  # 19
        "class h:\n"  # 20
        "    pass\n"  # 21
    )
    extraction = extract(source)
    by_name = {symbol.qualified_name: symbol for symbol in extraction.symbols}
    assert len(extraction.symbols) == len(by_name) == 6
    assert by_name["C.value"].span == SourceSpan(2, 7)
    assert by_name["C.value"].kind is SymbolKind.METHOD
    assert by_name["f"].span == SourceSpan(9, 14)
    assert by_name["g"].span == SourceSpan(16, 18)
    assert by_name["h"].kind is SymbolKind.CLASS
    assert by_name["h"].span == SourceSpan(19, 21)
    function_then_class = extract("class h:\n    pass\ndef h(): pass\n")
    last = {symbol.qualified_name: symbol.kind for symbol in function_then_class.symbols}
    assert last["h"] is SymbolKind.FUNCTION


def test_spans_include_decorators() -> None:
    source = "\n@first\n@second(\n    1,\n)\ndef f():\n    return 1\n\n\nclass C:\n    pass\n"
    assert spans(source) == {
        MODULE_QUALIFIED_NAME: (1, 11),
        "f": (2, 7),
        "C": (10, 11),
    }


@pytest.mark.parametrize(
    ("source", "lines"),
    [
        ("", 1),
        ("\n", 1),
        ("x = 1", 1),
        ("x = 1\ny = 2", 2),
        ("x = 1\ny = 2\n", 2),
        ("x = 1\r\ny = 2\r\n", 2),
        ("x = 1\ry = 2\r", 2),
        ("x = 1\n\n\n", 3),
        ("x = '\x0c'\n", 1),
        ("x = '\u2028'\n", 1),
        ("x = '''a\nb'''\n", 2),
    ],
)
def test_module_span_counts_physical_lines(source: str, lines: int) -> None:
    assert spans(source)[MODULE_QUALIFIED_NAME] == (1, lines)


def test_non_ascii_and_overlong_names_are_skipped_with_members() -> None:
    long_name = "a" * 290
    source = (
        "def caf\u00e9(): pass\n"
        "class \u00c9t\u00e9:\n"
        "    def m(self): pass\n"
        f"class {long_name}:\n"
        "    def short(self): pass\n"
        "    def within_limit_but_too_long_qualified_name(self): pass\n"
        "def ok(): pass\n"
    )
    extraction = extract(source)
    assert {symbol.qualified_name for symbol in extraction.symbols} == {
        MODULE_QUALIFIED_NAME,
        long_name,
        f"{long_name}.short",
        "ok",
    }
    assert extraction.skipped_definitions == 3


def test_top_level_def_named___module___is_skipped() -> None:
    extraction = extract(
        "def __module__(): pass\nclass C:\n    def __module__(self): pass\n"
        "class __module__:\n    def m(self): pass\n"
    )
    names = {symbol.qualified_name: symbol.kind for symbol in extraction.symbols}
    assert names == {
        MODULE_QUALIFIED_NAME: SymbolKind.MODULE,
        "C": SymbolKind.CLASS,
        "C.__module__": SymbolKind.METHOD,
    }
    assert extraction.skipped_definitions == 2


def test_symbol_and_node_limits_give_too_complex() -> None:
    source = "def a(): pass\ndef b(): pass\n"
    assert issue(source, IndexLimits(max_symbols_per_file=3)) is None
    assert issue(source, IndexLimits(max_symbols_per_file=2)) is FileIssueKind.TOO_COMPLEX
    nodes = sum(1 for _ in ast.walk(ast.parse(source)))
    assert issue(source, IndexLimits(max_ast_nodes_per_file=nodes)) is None
    assert issue(source, IndexLimits(max_ast_nodes_per_file=nodes - 1)) is (
        FileIssueKind.TOO_COMPLEX
    )


# ---------------------------------------------------------------------- decoding


def test_utf8_bom_and_cookies_decode() -> None:
    assert decode_source("x = '\u00e9'\n".encode()) == "x = '\u00e9'\n"
    assert decode_source(b"\xef\xbb\xbfx = 1\n") == "x = 1\n"
    assert decode_source(b"\xef\xbb\xbf# coding: utf-8\nx = 1\n") == "# coding: utf-8\nx = 1\n"
    latin = b"# -*- coding: latin-1 -*-\nx = '\xe9'\n"
    assert decode_source(latin) == "# -*- coding: latin-1 -*-\nx = '\u00e9'\n"
    assert kinds(latin) == {MODULE_QUALIFIED_NAME: SymbolKind.MODULE}
    second_line = b"#!/usr/bin/env python\n# vim: set fileencoding=iso-8859-1 :\nx = '\xe9'\n"
    assert isinstance(decode_source(second_line), str)
    assert "\u00e9" in str(decode_source(second_line))
    after_code = b"x = 1\n# coding: latin-1\ny = '\xe9'\n"
    assert decode_source(after_code) is FileIssueKind.DECODE_ERROR
    for name in (b"utf8", b"UTF-8", b"utf_8", b"utf-8-sig", b"latin1", b"ISO-8859-1", b"ascii"):
        assert isinstance(decode_source(b"# coding=" + name + b"\nx = 1\n"), str), name
    assert decode_source(b"# coding: us-ascii\nx = '\xe9'\n") is FileIssueKind.DECODE_ERROR


@pytest.mark.parametrize("name", [b"utf-16", b"rot13", b"unicode_escape", b"evilcodec", b"cp1252"])
def test_unsupported_encodings(name: bytes) -> None:
    source = b"# -*- coding: " + name + b" -*-\nx = 1\n"
    assert issue(source) is FileIssueKind.UNSUPPORTED_ENCODING


def test_decode_errors() -> None:
    assert issue(b"\xef\xbb\xbf# coding: latin-1\nx = 1\n") is FileIssueKind.DECODE_ERROR
    assert issue(b"x = '\xff\xfe'\n") is FileIssueKind.DECODE_ERROR
    assert issue(b"\xef\xbb\xbf# coding: rot13\nx = 1\n") is FileIssueKind.UNSUPPORTED_ENCODING


def test_nul_is_binary() -> None:
    assert issue(b"x = 1\x00\n") is FileIssueKind.BINARY
    assert issue(b"# coding: rot13\n\x00") is FileIssueKind.BINARY


@pytest.mark.parametrize(
    "source",
    [
        "def f(:\n    pass\n",
        "def f():\npass\n",
        "if x:\n        a = 1\n    b = 2\n",
        "if x:\n\ta = 1\n        b = 2\n",
        "x = 1" + "0" * 5000 + "\n",
        "f(**x, *y)\n",
    ],
)
def test_indentation_and_tab_errors_are_syntax_errors(source: str) -> None:
    assert issue(source) is FileIssueKind.SYNTAX_ERROR


ALLOWLISTED = [
    "utf-8",
    "utf8",
    "UTF-8",
    "utf_8",
    "latin-1",
    "latin1",
    "iso-8859-1",
    "iso8859-1",
    "iso-latin-1",
    "Latin-1",
    "ascii",
    "us-ascii",
]


@settings(max_examples=150, deadline=None)
@given(
    st.sampled_from(ALLOWLISTED),
    st.sampled_from(["# coding: {}", "# -*- coding: {} -*-", "#vim: fileencoding={}"]),
    st.booleans(),
    st.binary(max_size=40).map(lambda raw: raw.replace(b"\n", b"").replace(b"\r", b"")),
)
def test_cookie_decoder_agrees_with_tokenize_on_allowlisted_names(
    name: str, template: str, second_line: bool, payload: bytes
) -> None:
    cookie = template.format(name).encode("ascii")
    header = (b"# first line\n" + cookie) if second_line else cookie
    data = header + b"\nx = 1\n# " + payload + b"\n"
    ours = decode_source(data)
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
        expected: str | None = data.decode(encoding)
    except (SyntaxError, UnicodeDecodeError):
        expected = None
    if expected is None:
        assert ours is FileIssueKind.DECODE_ERROR
    else:
        assert ours == expected


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=300))
def test_extract_never_raises_on_arbitrary_bytes(data: bytes) -> None:
    extraction = EXTRACTOR.extract(data, DEFAULT_INDEX_LIMITS)
    assert isinstance(extraction, FileExtraction)
    assert (extraction.issue is None) == bool(extraction.symbols)


@settings(max_examples=200, deadline=None)
@given(
    st.text(
        alphabet=st.sampled_from(list("defclas():\n pf1x=#'\"\\\t\r@.\u00e9")),
        max_size=120,
    )
)
def test_extract_never_raises_on_python_like_text(text: str) -> None:
    extraction = EXTRACTOR.extract(text.encode("utf-8", "surrogatepass"), DEFAULT_INDEX_LIMITS)
    assert isinstance(extraction, FileExtraction)


def test_unsupported_syntax_is_a_whole_file_issue(monkeypatch: pytest.MonkeyPatch) -> None:
    from asca.infrastructure.indexing import python_symbols
    from asca.infrastructure.indexing.python_fingerprint import UnsupportedSyntax

    def unsupported(tree: ast.Module) -> dict[int, str]:
        raise UnsupportedSyntax("a node type from a newer interpreter")

    monkeypatch.setattr(python_symbols, "definition_digests", unsupported)
    assert issue("def f():\n    pass\n") is FileIssueKind.UNSUPPORTED_SYNTAX
