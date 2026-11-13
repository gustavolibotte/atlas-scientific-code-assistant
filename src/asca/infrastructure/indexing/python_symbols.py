"""Python symbol extractor: bytes of one file in, symbols with ``python-ast/1`` fingerprints out.

The extractor never receives a path, never imports, compiles or executes the code, and
never looks a codec up by an untrusted name: it decodes with its own PEP 263 reader and a
fixed allowlist of encodings. It is total: every input gives a :class:`FileExtraction`,
and an issue never carries an exception message, because messages echo source text.
"""

import ast
import re
import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from asca.application.ports import ExtractedSymbol, FileExtraction, IndexLimits
from asca.domain.provenance import (
    MODULE_QUALIFIED_NAME,
    QUALIFIED_NAME_MAX,
    FileIssueKind,
    FingerprintAlgorithm,
    Language,
    SourceSpan,
    SymbolKind,
)
from asca.infrastructure.indexing.python_fingerprint import (
    UnsupportedSyntax,
    definition_digests,
    merge_digests,
    module_digest,
)

COOKIE_RE: Final = re.compile(rb"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)", re.ASCII)
BLANK_RE: Final = re.compile(rb"^[ \t\f]*(?:[#\r\n]|$)", re.ASCII)
_BOM: Final = b"\xef\xbb\xbf"
_IDENTIFIER: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*", re.ASCII)
_UTF8: Final = "utf-8"
_LATIN1: Final = "iso8859-1"
_LATIN1_NAMES: Final = ("latin-1", "latin1", "iso-8859-1", "iso8859-1", "iso-latin-1")
_ASCII_NAMES: Final = ("ascii", "us-ascii")
_PARSE_FILENAME: Final = "<asca-index>"

_Definition = ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef


class _Failed(Exception):  # noqa: N818 - internal control flow, never escapes
    def __init__(self, issue: FileIssueKind) -> None:
        super().__init__(issue.value)
        self.issue = issue


def _normal_encoding(name: bytes) -> str:
    """Map a cookie name onto the allowlist; anything else is unsupported."""
    normal = name.decode("ascii").lower().replace("_", "-")
    if normal in ("utf-8", "utf8") or normal.startswith("utf-8-"):
        return _UTF8
    if normal in _LATIN1_NAMES or normal.startswith(tuple(item + "-" for item in _LATIN1_NAMES)):
        return _LATIN1
    if normal in _ASCII_NAMES:
        return "ascii"
    raise _Failed(FileIssueKind.UNSUPPORTED_ENCODING)


def _cookie(lines: Sequence[bytes]) -> bytes | None:
    """The PEP 263 cookie of the first line, or of a blank or comment first line's next."""
    match = COOKIE_RE.match(lines[0])
    if match is not None:
        return match.group(1)
    if len(lines) > 1 and BLANK_RE.match(lines[0]) is not None:
        match = COOKIE_RE.match(lines[1])
        if match is not None:
            return match.group(1)
    return None


def _decode(data: bytes) -> str:
    """PEP 263 decoding with a fixed codec allowlist; raises ``_Failed``."""
    bom = data.startswith(_BOM)
    if bom:
        data = data[len(_BOM) :]
    cookie = _cookie(data.split(b"\n", 2)[:2])
    encoding = _UTF8 if cookie is None else _normal_encoding(cookie)
    if bom and encoding != _UTF8:
        raise _Failed(FileIssueKind.DECODE_ERROR)
    try:
        return data.decode(encoding, "strict")
    except UnicodeDecodeError:
        raise _Failed(FileIssueKind.DECODE_ERROR) from None


def decode_source(data: bytes) -> str | FileIssueKind:
    """Decode like PEP 263 without any codec lookup; return the text or the issue."""
    try:
        return _decode(data)
    except _Failed as failure:
        return failure.issue


def _parse(text: str) -> ast.Module:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(text, filename=_PARSE_FILENAME, mode="exec")
    except (SyntaxError, ValueError):
        raise _Failed(FileIssueKind.SYNTAX_ERROR) from None
    except (RecursionError, MemoryError):
        raise _Failed(FileIssueKind.TOO_COMPLEX) from None


def _check_node_count(tree: ast.Module, limit: int) -> None:
    for count, _ in enumerate(ast.walk(tree), start=1):
        if count > limit:
            raise _Failed(FileIssueKind.TOO_COMPLEX)


@dataclass(frozen=True, slots=True)
class _Occurrence:
    qualified_name: str
    kind: SymbolKind
    node: _Definition


def _children(statement: ast.stmt) -> list[list[ast.stmt]]:
    """Statement blocks of a compound statement that share its class scope."""
    if isinstance(statement, ast.If | ast.For | ast.AsyncFor | ast.While):
        return [statement.body, statement.orelse]
    if isinstance(statement, ast.With | ast.AsyncWith):
        return [statement.body]
    if isinstance(statement, ast.Try | ast.TryStar):
        blocks = [statement.body]
        blocks += [handler.body for handler in statement.handlers]
        return [*blocks, statement.orelse, statement.finalbody]
    if isinstance(statement, ast.Match):
        return [case.body for case in statement.cases]
    return []


def _occurrences(tree: ast.Module) -> tuple[list[_Occurrence], int]:
    """Module-level, class-level and conditional definitions; never function bodies."""
    found: list[_Occurrence] = []
    skipped = 0
    pending: list[tuple[list[ast.stmt], tuple[str, ...]]] = [(tree.body, ())]
    while pending:
        statements, chain = pending.pop()
        for statement in statements:
            if not isinstance(statement, _Definition):
                pending.extend((block, chain) for block in _children(statement))
                continue
            name = statement.name
            qualified_name = ".".join((*chain, name))
            if (
                _IDENTIFIER.fullmatch(name) is None
                or (not chain and name == MODULE_QUALIFIED_NAME)
                or len(qualified_name) > QUALIFIED_NAME_MAX
            ):
                skipped += 1
                continue
            if isinstance(statement, ast.ClassDef):
                kind = SymbolKind.CLASS
                pending.append((statement.body, (*chain, name)))
            else:
                kind = SymbolKind.METHOD if chain else SymbolKind.FUNCTION
            found.append(_Occurrence(qualified_name, kind, statement))
    return found, skipped


def _span(node: _Definition) -> tuple[int, int]:
    start = min([node.lineno, *(item.lineno for item in node.decorator_list)])
    end = node.end_lineno if node.end_lineno is not None else start
    return start, end


def _module_span(text: str) -> SourceSpan:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.count("\n") + (1 if normalized and not normalized.endswith("\n") else 0)
    return SourceSpan(1, max(1, lines))


def _symbols(
    tree: ast.Module, text: str, digests: dict[int, str], module_fingerprint: str
) -> tuple[list[ExtractedSymbol], int]:
    occurrences, skipped = _occurrences(tree)
    grouped: dict[str, list[_Occurrence]] = {}
    for occurrence in occurrences:
        grouped.setdefault(occurrence.qualified_name, []).append(occurrence)
    symbols = [
        ExtractedSymbol(
            SymbolKind.MODULE, MODULE_QUALIFIED_NAME, _module_span(text), module_fingerprint
        )
    ]
    for qualified_name, group in grouped.items():
        group.sort(key=lambda item: (item.node.lineno, item.node.col_offset))
        spans = [_span(item.node) for item in group]
        symbols.append(
            ExtractedSymbol(
                kind=group[-1].kind,
                qualified_name=qualified_name,
                span=SourceSpan(min(start for start, _ in spans), max(end for _, end in spans)),
                fingerprint=merge_digests([digests[id(item.node)] for item in group]),
            )
        )
    return symbols, skipped


def _extract(data: bytes, limits: IndexLimits) -> FileExtraction:
    if b"\x00" in data:
        raise _Failed(FileIssueKind.BINARY)
    text = _decode(data)
    tree = _parse(text)
    _check_node_count(tree, limits.max_ast_nodes_per_file)
    try:
        digests = definition_digests(tree)
        module_fingerprint = module_digest(tree, digests)
    except UnsupportedSyntax:
        raise _Failed(FileIssueKind.UNSUPPORTED_SYNTAX) from None
    symbols, skipped = _symbols(tree, text, digests, module_fingerprint)
    if len(symbols) > limits.max_symbols_per_file:
        raise _Failed(FileIssueKind.TOO_COMPLEX)
    return FileExtraction(
        issue=None,
        symbols=tuple(sorted(symbols, key=lambda item: item.qualified_name)),
        skipped_definitions=skipped,
    )


class PythonAstExtractor:
    """``SymbolExtractor`` for ``.py`` files with fingerprint algorithm ``python-ast/1``."""

    __slots__ = ()

    @property
    def language(self) -> Language:
        return Language.PYTHON

    @property
    def algorithm(self) -> FingerprintAlgorithm:
        return FingerprintAlgorithm.PYTHON_AST_1

    @property
    def suffixes(self) -> frozenset[str]:
        return frozenset({".py"})

    def extract(self, data: bytes, limits: IndexLimits) -> FileExtraction:
        """Total: never raises for any ``data``; failures become a file issue."""
        try:
            return _extract(data, limits)
        except _Failed as failure:
            return FileExtraction(issue=failure.issue, symbols=(), skipped_definitions=0)
