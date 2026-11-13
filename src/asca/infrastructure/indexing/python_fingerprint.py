"""Fingerprint algorithm ``python-ast/1``: a canonical, closed-world AST serializer.

The serializer walks a pinned field table (never derived from the running interpreter),
encodes scalars with explicit type tags and references nested definitions by their own
digest (a Merkle tree). A definition's digest never contains its own name, and a bare
``Name`` equal to the enclosing module-level definition name is encoded as ``@top``, so
renaming a recursive function or a class that mentions itself is still a move.
Docstrings and every other no-op string statement are dropped; f-strings are normalized.
Nothing here recurses in Python, so deep inputs never hit the recursion limit.

Any change of output for an input that already had a fingerprint needs a new algorithm
id (ADR 0039, versioning policy).
"""

import ast
import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

ALGORITHM_PREFIX: Final = b"asca:python-ast/1\n"
MERGED_PREFIX: Final = b"asca:python-ast/1:merged\n"

#: Hashed fields per node type, in the 3.13 ``_fields`` order minus the never-hashed
#: fields (positions, ``ctx``, ``type_comment``, ``Constant.kind``,
#: ``Module.type_ignores``). Leaf nodes have no fields. Types that are not listed raise
#: :class:`UnsupportedSyntax`.
FIELD_TABLE: Final[Mapping[str, tuple[str, ...]]] = {
    "Add": (),
    "And": (),
    "AnnAssign": ("target", "annotation", "value", "simple"),
    "Assert": ("test", "msg"),
    "Assign": ("targets", "value"),
    "AsyncFor": ("target", "iter", "body", "orelse"),
    "AsyncFunctionDef": ("name", "args", "body", "decorator_list", "returns", "type_params"),
    "AsyncWith": ("items", "body"),
    "Attribute": ("value", "attr"),
    "AugAssign": ("target", "op", "value"),
    "Await": ("value",),
    "BinOp": ("left", "op", "right"),
    "BitAnd": (),
    "BitOr": (),
    "BitXor": (),
    "BoolOp": ("op", "values"),
    "Break": (),
    "Call": ("func", "args", "keywords"),
    "ClassDef": ("name", "bases", "keywords", "body", "decorator_list", "type_params"),
    "Compare": ("left", "ops", "comparators"),
    "Constant": ("value",),
    "Continue": (),
    "Delete": ("targets",),
    "Dict": ("keys", "values"),
    "DictComp": ("key", "value", "generators"),
    "Div": (),
    "Eq": (),
    "ExceptHandler": ("type", "name", "body"),
    "Expr": ("value",),
    "FloorDiv": (),
    "For": ("target", "iter", "body", "orelse"),
    "FormattedValue": ("value", "conversion", "format_spec"),
    "FunctionDef": ("name", "args", "body", "decorator_list", "returns", "type_params"),
    "GeneratorExp": ("elt", "generators"),
    "Global": ("names",),
    "Gt": (),
    "GtE": (),
    "If": ("test", "body", "orelse"),
    "IfExp": ("test", "body", "orelse"),
    "Import": ("names",),
    "ImportFrom": ("module", "names", "level"),
    "In": (),
    "Invert": (),
    "Is": (),
    "IsNot": (),
    "JoinedStr": ("values",),
    "LShift": (),
    "Lambda": ("args", "body"),
    "List": ("elts",),
    "ListComp": ("elt", "generators"),
    "Lt": (),
    "LtE": (),
    "MatMult": (),
    "Match": ("subject", "cases"),
    "MatchAs": ("pattern", "name"),
    "MatchClass": ("cls", "patterns", "kwd_attrs", "kwd_patterns"),
    "MatchMapping": ("keys", "patterns", "rest"),
    "MatchOr": ("patterns",),
    "MatchSequence": ("patterns",),
    "MatchSingleton": ("value",),
    "MatchStar": ("name",),
    "MatchValue": ("value",),
    "Mod": (),
    "Module": ("body",),
    "Mult": (),
    "Name": ("id",),
    "NamedExpr": ("target", "value"),
    "Nonlocal": ("names",),
    "Not": (),
    "NotEq": (),
    "NotIn": (),
    "Or": (),
    "ParamSpec": ("name", "default_value"),
    "Pass": (),
    "Pow": (),
    "RShift": (),
    "Raise": ("exc", "cause"),
    "Return": ("value",),
    "Set": ("elts",),
    "SetComp": ("elt", "generators"),
    "Slice": ("lower", "upper", "step"),
    "Starred": ("value",),
    "Sub": (),
    "Subscript": ("value", "slice"),
    "Try": ("body", "handlers", "orelse", "finalbody"),
    "TryStar": ("body", "handlers", "orelse", "finalbody"),
    "Tuple": ("elts",),
    "TypeAlias": ("name", "type_params", "value"),
    "TypeVar": ("name", "bound", "default_value"),
    "TypeVarTuple": ("name", "default_value"),
    "UAdd": (),
    "USub": (),
    "UnaryOp": ("op", "operand"),
    "While": ("test", "body", "orelse"),
    "With": ("items", "body"),
    "Yield": ("value",),
    "YieldFrom": ("value",),
    "alias": ("name", "asname"),
    "arg": ("arg", "annotation"),
    "arguments": (
        "posonlyargs",
        "args",
        "vararg",
        "kwonlyargs",
        "kw_defaults",
        "kwarg",
        "defaults",
    ),
    "comprehension": ("target", "iter", "ifs", "is_async"),
    "keyword": ("arg", "value"),
    "match_case": ("pattern", "guard", "body"),
    "withitem": ("context_expr", "optional_vars"),
}

_DEFINITIONS: Final = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_STATEMENT_LISTS: Final = frozenset({"body", "orelse", "finalbody"})
#: Exact node type -> table name, for the types that exist on this interpreter.
_NODE_NAMES: Final[Mapping[type, str]] = {
    node_type: name
    for name in FIELD_TABLE
    if isinstance(node_type := getattr(ast, name, None), type)
}


class UnsupportedSyntax(Exception):  # noqa: N818 - name fixed by the M2 specification
    """The tree holds a node type or constant outside the pinned table."""


@dataclass(frozen=True, slots=True)
class _Literal:
    """Pre-encoded output on the work stack (never a value from the tree)."""

    data: bytes


_TILDE: Final = _Literal(b"~")
_OPEN_LIST: Final = b"["
_CLOSE_LIST: Final = _Literal(b"]")
_CLOSE_NODE: Final = _Literal(b")")
_SPACE: Final = _Literal(b" ")
_FIELD_LITERALS: Final[Mapping[str, _Literal]] = {
    field: _Literal(b" " + field.encode("ascii") + b"=")
    for fields in FIELD_TABLE.values()
    for field in fields
}


def _text(value: str) -> bytes:
    data = value.encode("utf-8", "surrogatepass")
    return b"s" + str(len(data)).encode("ascii") + b":" + data


def _integer(value: int) -> bytes:
    sign = b"-" if value < 0 else b""
    return b"i" + sign + format(abs(value), "x").encode("ascii") + b";"


def _constant(value: object) -> bytes:
    if value is None:
        return b"N"
    if value is True:
        return b"T"
    if value is False:
        return b"F"
    if value is Ellipsis:
        return b"E"
    if type(value) is int:
        return _integer(value)
    if type(value) is float:
        return b"f" + value.hex().encode("ascii") + b";"
    if type(value) is complex:
        real, imag = value.real.hex(), value.imag.hex()
        return b"c" + real.encode("ascii") + b"," + imag.encode("ascii") + b";"
    if type(value) is str:
        return _text(value)
    if type(value) is bytes:
        return b"b" + str(len(value)).encode("ascii") + b":" + value
    raise UnsupportedSyntax("unsupported constant type")


def _is_string_statement(node: object) -> bool:
    return (
        type(node) is ast.Expr
        and type(node.value) is ast.Constant
        and type(node.value.value) is str
    )


def _joined_values(values: object) -> list[object]:
    """N2: flatten nested JoinedStr, drop empty strings, merge adjacent strings."""
    if not isinstance(values, list):
        raise UnsupportedSyntax("JoinedStr.values must be a list")
    result: list[object] = []
    pending: list[object] = list(reversed(values))
    while pending:
        item = pending.pop()
        if type(item) is ast.JoinedStr:
            nested = item.values
            if not isinstance(nested, list):
                raise UnsupportedSyntax("JoinedStr.values must be a list")
            pending.extend(reversed(nested))
            continue
        if type(item) is ast.Constant and type(item.value) is str:
            if item.value == "":
                continue
            last = result[-1] if result else None
            if type(last) is ast.Constant and type(last.value) is str:
                result[-1] = ast.Constant(last.value + item.value)
                continue
            result.append(ast.Constant(item.value))
            continue
        result.append(item)
    return result


def _fields(node: ast.AST, name: str) -> list[tuple[str, object]]:
    """FIELDS(N): the emitted ``(field, value)`` pairs of ``node`` after N1-N4."""
    emitted: list[tuple[str, object]] = []
    is_definition = isinstance(node, _DEFINITIONS)
    for field in FIELD_TABLE[name]:
        if is_definition and field == "name":
            continue
        value = getattr(node, field, None)
        if field in _STATEMENT_LISTS and isinstance(value, list):
            value = [item for item in value if not _is_string_statement(item)]
        elif name == "JoinedStr" and field == "values":
            value = _joined_values(value)
        elif name == "FormattedValue" and field == "format_spec":
            if type(value) is ast.JoinedStr and not _joined_values(value.values):
                value = None
        elif name == "ImportFrom" and field == "level" and value is None:
            value = 0
        if value is None or (isinstance(value, list) and not value):
            continue
        emitted.append((field, value))
    return emitted


def _digest(root: ast.AST, top: str | None, digests: Mapping[int, str]) -> str:
    """sha256 of the prefix and ENC(root); nested definitions come from ``digests``."""
    out = bytearray(ALGORITHM_PREFIX)
    stack: list[object] = [root]
    while stack:
        item = stack.pop()
        if type(item) is _Literal:
            out += item.data
        elif item is None:
            out += b"~"
        elif isinstance(item, list):
            out += _OPEN_LIST
            stack.append(_CLOSE_LIST)
            for element in reversed(item):
                stack.append(element)
                stack.append(_SPACE)
        elif type(item) is str:
            out += _text(item)
        elif type(item) is int:
            out += _integer(item)
        elif isinstance(item, ast.AST):
            _encode_node(item, root, top, digests, out, stack)
        else:
            raise UnsupportedSyntax("unsupported field value type")
    return hashlib.sha256(bytes(out)).hexdigest()


def _encode_node(
    node: ast.AST,
    root: ast.AST,
    top: str | None,
    digests: Mapping[int, str],
    out: bytearray,
    stack: list[object],
) -> None:
    name = _NODE_NAMES.get(type(node))
    if name is None:
        raise UnsupportedSyntax("unsupported node type")
    if isinstance(node, _DEFINITIONS) and node is not root:
        out += b"(@def " + _text(node.name) + b" " + digests[id(node)].encode("ascii") + b")"
        return
    if type(node) is ast.Name and top is not None and node.id == top:
        out += b"(Name @top)"
        return
    if type(node) is ast.Constant or type(node) is ast.MatchSingleton:
        out += b"(" + name.encode("ascii") + b" value=" + _constant(node.value) + b")"
        return
    out += b"(" + name.encode("ascii")
    stack.append(_CLOSE_NODE)
    for field, value in reversed(_fields(node, name)):
        stack.append(value)
        stack.append(_FIELD_LITERALS[field])


def definition_digests(tree: ast.Module) -> dict[int, str]:
    """Digest of every definition node in ``tree``, keyed by ``id(node)``.

    Raise :class:`UnsupportedSyntax` for a node or constant outside the table.
    """
    found: list[tuple[int, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef, str]] = []
    pending: list[tuple[ast.AST, str | None, int]] = [(tree, None, 0)]
    while pending:
        node, top, depth = pending.pop()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, _DEFINITIONS):
                child_top = top if top is not None else child.name
                found.append((depth + 1, child, child_top))
                pending.append((child, child_top, depth + 1))
            else:
                pending.append((child, top, depth))
    found.sort(key=lambda entry: -entry[0])
    digests: dict[int, str] = {}
    for _, definition, top_name in found:
        digests[id(definition)] = _digest(definition, top_name, digests)
    return digests


def module_digest(tree: ast.Module, digests: Mapping[int, str]) -> str:
    """Digest of the whole module; ``digests`` comes from :func:`definition_digests`."""
    if type(tree) is not ast.Module:
        raise UnsupportedSyntax("the root must be a Module")
    return _digest(tree, None, digests)


def merge_digests(digests: Sequence[str]) -> str:
    """One fingerprint for several definitions of one qualified name, in source order."""
    if not digests:
        raise ValueError("at least one digest is needed")
    if len(digests) == 1:
        return digests[0]
    joined = b"".join(digest.encode("ascii") + b"\n" for digest in digests)
    return hashlib.sha256(MERGED_PREFIX + joined).hexdigest()
