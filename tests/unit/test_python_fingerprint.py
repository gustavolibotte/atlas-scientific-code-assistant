"""Fingerprint algorithm ``python-ast/1``: normalizations, coverage and robustness."""

import ast
import io
import random
import sys
import tokenize
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from asca.application.ports import DEFAULT_INDEX_LIMITS
from asca.infrastructure.indexing.python_fingerprint import (
    ALGORITHM_PREFIX,
    FIELD_TABLE,
    UnsupportedSyntax,
    definition_digests,
    merge_digests,
    module_digest,
)
from asca.infrastructure.indexing.python_symbols import PythonAstExtractor

pytestmark = pytest.mark.unit

SOURCE_ROOT = Path(__file__).resolve().parents[2] / "src" / "asca"
REPOSITORY_SOURCES = sorted(SOURCE_ROOT.rglob("*.py"))
EXTRACTOR = PythonAstExtractor()


def fingerprints(source: str | bytes) -> dict[str, str]:
    data = source.encode("utf-8") if isinstance(source, str) else source
    extraction = EXTRACTOR.extract(data, DEFAULT_INDEX_LIMITS)
    assert extraction.issue is None, extraction.issue
    return {symbol.qualified_name: symbol.fingerprint for symbol in extraction.symbols}


def fp(source: str | bytes, qualified_name: str = "f") -> str:
    return fingerprints(source)[qualified_name]


# ---------------------------------------------------------------------- formatting

BASE = (
    "import math\n"
    "\n"
    "\n"
    "def f(a, b=(1, 2), *args, c: int = 3, **kwargs) -> float:\n"
    "    total = math.fsum([a, b[0], c])\n"
    "    if total > 10 and not kwargs:\n"
    "        return total * 2\n"
    "    return g(total, a, key='v')\n"
    "\n"
    "\n"
    "class C:\n"
    "    def m(self, x):\n"
    "        return [x, x + 1]\n"
)

FORMATTED = {
    "whitespace_parentheses_wrapping_trailing_commas": (
        "import math\n"
        "def f(a, b = ( 1 , 2 ,), *args, c : int=3, **kwargs,)->float:\n"
        "    total = (math.fsum(\n"
        "        [a,\n"
        "         b[0],\n"
        "         c,],\n"
        "    ))\n"
        "    if (total > 10) and (not kwargs):\n"
        "        return (total) * (2)\n"
        "    return g(total,\n"
        "             a,\n"
        '             key="v",)\n'
        "class C :\n"
        "    def m( self,x ):\n"
        "        return [ x,\n"
        "                 x+1 ]\n"
    ),
    "comments_and_blank_lines": (
        "# leading comment\n"
        "import math  # trailing\n"
        "\n\n\n"
        "def f(a, b=(1, 2), *args, c: int = 3, **kwargs) -> float:  # sig\n"
        "    # body comment\n"
        "    total = math.fsum([a, b[0], c])\n"
        "\n"
        "    if total > 10 and not kwargs:\n"
        "        return total * 2  # double\n"
        "    return g(total, a, key='v')\n"
        "# between\n"
        "\n"
        "class C:\n"
        "\n"
        "    def m(self, x):\n"
        "        # only a comment\n"
        "        return [x, x + 1]\n"
        "# end\n"
    ),
    "crlf": BASE.replace("\n", "\r\n"),
    "bom": "\ufeff" + BASE,
    "latin1_cookie_on_ascii": "# -*- coding: latin-1 -*-\n" + BASE,
}


@pytest.mark.parametrize("variant", sorted(FORMATTED))
def test_formatting_and_comments_do_not_change_fingerprints(variant: str) -> None:
    assert fingerprints(FORMATTED[variant]) == fingerprints(BASE)


def test_docstrings_and_no_op_strings_are_ignored() -> None:
    documented = (
        '"""Module docstring."""\n'
        "def f():\n"
        "    '''Function docstring.'''\n"
        "    x = 1\n"
        "    'a no-op string in the middle'\n"
        "    return x\n"
        "class C:\n"
        '    """Class docstring."""\n'
        "    y = 2\n"
        '    """Attribute docstring."""\n'
        "    def m(self):\n"
        "        'Method docstring.'\n"
        "        if self:\n"
        "            'nested no-op'\n"
        "            return 1\n"
        "        else:\n"
        "            'else no-op'\n"
        "        return 2\n"
    )
    plain = (
        "def f():\n"
        "    x = 1\n"
        "    return x\n"
        "class C:\n"
        "    y = 2\n"
        "    def m(self):\n"
        "        if self:\n"
        "            return 1\n"
        "        return 2\n"
    )
    assert fingerprints(documented) == fingerprints(plain)
    with_pass = plain.replace(
        "            return 1\n", "            return 1\n        else:\n            pass\n"
    )
    assert fingerprints(with_pass)["C.m"] != fingerprints(plain)["C.m"]
    # Bytes and f-string expression statements are not no-op strings.
    assert fp("def f():\n    b'x'\n") != fp("def f():\n    pass\n")
    assert fp("def f():\n    f'{x}'\n") != fp("def f():\n    pass\n")


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("1000", "1_000"),
        ("1000", "0x3e8"),
        ("1000", "0o1750"),
        ("1000", "0b1111101000"),
        ("1.", "1.0"),
        ("1e3", "1000.0"),
        ("'ab'", '"ab"'),
        ("'ab'", "u'ab'"),
        ("'ab'", "'a' \"b\""),
        ("'ab'", "'\\x61b'"),
        ("'ab'", "'''ab'''"),
        ("f'a{x}b'", "f'a{x}' 'b'"),
        ("f'a{x}b'", "f'a' f'{x}' f'b'"),
        ("f'{x}'", "f'{x:}'"),
        ("b'ab'", "b'a' b'b'"),
    ],
)
def test_equal_spellings(left: str, right: str) -> None:
    assert fp(f"def f(x):\n    return {left}\n") == fp(f"def f(x):\n    return {right}\n")


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("def f():\n    return 1\n", "def f():\n    return 1.0\n"),
        ("def f():\n    return 1\n", "def f():\n    return True\n"),
        ("def f():\n    return 1.0\n", "def f():\n    return True\n"),
        ("def f():\n    return 1\n", "def f():\n    return 1j\n"),
        ("def f():\n    return 1\n", "def f():\n    return b'1'\n"),
        ("def f():\n    return 1\n", "def f():\n    return '1'\n"),
        ("def f():\n    return b'1'\n", "def f():\n    return '1'\n"),
        ("def f():\n    return 0.0\n", "def f():\n    return -0.0\n"),
        ("def f():\n    return None\n", "def f():\n    return\n"),
        ("def f():\n    return '\u00e9'\n", "def f():\n    return 'e\u0301'\n"),
        ("def f():\n    pass\n", "@d\ndef f():\n    pass\n"),
        ("@d\ndef f():\n    pass\n", "@e\ndef f():\n    pass\n"),
        ("def f(x: int):\n    pass\n", "def f(x: str):\n    pass\n"),
        ("def f(x):\n    pass\n", "def f(x: int):\n    pass\n"),
        ("def f() -> int:\n    pass\n", "def f():\n    pass\n"),
        ("def f(x=1):\n    pass\n", "def f(x=2):\n    pass\n"),
        ("def f(*, x=1):\n    pass\n", "def f(*, x=2):\n    pass\n"),
        ("def f(x, /):\n    pass\n", "def f(x):\n    pass\n"),
        ("def f():\n    return 1\n", "async def f():\n    return 1\n"),
        ("def f():\n    pass\n", "def f():\n    ...\n"),
        ("def f(x):\n    return x\n", "def f(y):\n    return y\n"),
        ("def f():\n    return 'ab'\n", "def f():\n    return f'ab'\n"),
        ("def f():\n    return x\n", "def f():\n    return y\n"),
        ("def f():\n    return a.b\n", "def f():\n    return a.c\n"),
        ("def f():\n    from . import a\n", "def f():\n    from .. import a\n"),
        ("def f():\n    import a\n", "def f():\n    import a as b\n"),
    ],
)
def test_semantic_differences(left: str, right: str) -> None:
    assert fp(left) != fp(right)


DEL_TARGETS = (
    "self.connection_pool_manager_instance",
    "self.authentication_token_cache_storage",
    "self.other_value",
)
#: A ``del`` statement longer than this repository's line length (100).
DEL_SOURCE = "class Session:\n    def close(self):\n        del " + ", ".join(DEL_TARGETS) + "\n"
#: ``DEL_SOURCE`` exactly as ``ruff format`` rewrites it with this repository's settings.
DEL_FORMATTED = (
    "class Session:\n    def close(self):\n        del (\n"
    + "".join(f"            {target},\n" for target in DEL_TARGETS)
    + "        )\n"
)


def test_formatter_parenthesized_del_keeps_every_fingerprint() -> None:
    assert max(len(line) for line in DEL_SOURCE.splitlines()) > 100
    assert fingerprints(DEL_SOURCE) == fingerprints(DEL_FORMATTED)


@pytest.mark.parametrize(
    "variant",
    [
        "del (a, b)\n",
        "del [a, b]\n",
        "del (a), b\n",
        "del (a,), [b]\n",
        "del ((a, b),)\n",
        "del [(a,), [[b]]]\n",
    ],
)
def test_del_targets_are_flattened(variant: str) -> None:
    assert fp(f"def f():\n    {variant}") == fp("def f():\n    del a, b\n")


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("del a, b\n", "del b, a\n"),
        ("del (a, b)\n", "del a\n"),
        ("del a[0], b\n", "del a, b\n"),
        ("del (a, b)\n", "(a, b)\n"),
    ],
)
def test_del_target_order_and_content_still_matter(left: str, right: str) -> None:
    assert fp(f"def f():\n    {left}") != fp(f"def f():\n    {right}")


def test_rename_keeps_function_fingerprint() -> None:
    assert fp("def f(x):\n    return x + 1\n") == fp("def g(x):\n    return x + 1\n", "g")


def test_recursive_rename_keeps_fingerprint() -> None:
    assert fp("def f(n):\n    return f(n - 1)\n") == fp("def g(n):\n    return g(n - 1)\n", "g")
    # A reference to another function is not the definition's own name.
    assert fp("def f(n):\n    return f(n - 1)\n") != fp("def g(n):\n    return f(n - 1)\n", "g")


def test_class_rename_keeps_class_and_method_fingerprints() -> None:
    template = (
        "class {0}(Base):\n"
        "    X = 1\n"
        "    def m(self) -> {0}:\n"
        "        super({0}, self).m()\n"
        "        return {0}.X\n"
    )
    old = fingerprints(template.format("C"))
    new = fingerprints(template.format("D"))
    assert old["C"] == new["D"]
    assert old["C.m"] == new["D.m"]
    assert old["__module__"] != new["__module__"]


def test_method_name_bare_reference_is_not_substituted() -> None:
    calls_fit = fingerprints("class C:\n    def fit(self):\n        return fit(self)\n")
    renamed = fingerprints("class C:\n    def go(self):\n        return fit(self)\n")
    renamed_call = fingerprints("class C:\n    def go(self):\n        return go(self)\n")
    assert calls_fit["C.fit"] == renamed["C.go"]
    assert calls_fit["C.fit"] != renamed_call["C.go"]


def test_method_edit_changes_class() -> None:
    old = fingerprints(
        "class C:\n    def m(self):\n        return 1\n    def n(self):\n        pass\n"
    )
    new = fingerprints(
        "class C:\n    def m(self):\n        return 2\n    def n(self):\n        pass\n"
    )
    assert old["C"] != new["C"]
    assert old["C.m"] != new["C.m"]
    assert old["C.n"] == new["C.n"]
    renamed = fingerprints(
        "class C:\n    def k(self):\n        return 1\n    def n(self):\n        pass\n"
    )
    assert old["C"] != renamed["C"]
    assert old["C.m"] == renamed["C.k"]


def test_nested_def_edit_or_rename_changes_enclosing_function() -> None:
    base = "def f():\n    def g():\n        return 1\n    return g\n"
    edited = "def f():\n    def g():\n        return 2\n    return g\n"
    renamed = "def f():\n    def h():\n        return 1\n    return g\n"
    nested_class = "def f():\n    class K:\n        pass\n    return K\n"
    assert len({fp(base), fp(edited), fp(renamed), fp(nested_class)}) == 4
    assert "f.g" not in fingerprints(base)


def test_merged_definitions_order_and_variant_count_matter() -> None:
    two = "if X:\n    def f():\n        return 1\nelse:\n    def f():\n        return 2\n"
    swapped = "if X:\n    def f():\n        return 2\nelse:\n    def f():\n        return 1\n"
    three = two + "def f():\n    return 3\n"
    single = "def f():\n    return 1\n"
    assert len({fp(two), fp(swapped), fp(three), fp(single)}) == 4
    first = fp("def f():\n    return 1\n")
    second = fp("def f():\n    return 2\n")
    assert fp(two) == merge_digests([first, second])
    assert merge_digests([first]) == first
    with pytest.raises(ValueError, match="at least one digest"):
        merge_digests([])


def test_huge_hex_literal_and_lone_surrogate_encode() -> None:
    huge = "def f():\n    return 0x" + "f" * 5000 + "\n"
    huger = "def f():\n    return 0x1" + "0" * 5000 + "\n"
    assert fp(huge) != fp(huger)
    surrogate = fp("def f():\n    return '\\ud800'\n")
    assert surrogate != fp("def f():\n    return '\\ud801'\n")
    assert surrogate != fp("def f():\n    return '\\U00010000'\n")


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 needs 3.12")
def test_pep695_distinguished() -> None:
    generic = fp("def f[T](x: T) -> T:\n    return x\n")
    plain = fp("def f(x: T) -> T:\n    return x\n")
    bounded = fp("def f[T: int](x: T) -> T:\n    return x\n")
    assert len({generic, plain, bounded}) == 3
    alias = fingerprints("type A[T] = list[T]\n")["__module__"]
    assert alias != fingerprints("type A = list[T]\n")["__module__"]


# ---------------------------------------------------------------------- closed world

UNSUPPORTED_NODES = frozenset(
    {"Interactive", "Expression", "FunctionType", "TypeIgnore", "Load", "Store", "Del"}
)
DEPRECATED_ALIASES = frozenset(
    {
        "AugLoad",
        "AugStore",
        "Bytes",
        "Ellipsis",
        "ExtSlice",
        "Index",
        "NameConstant",
        "Num",
        "Param",
        "Str",
        "Suite",
    }
)
ABSTRACT_BASES = frozenset(
    {
        "AST",
        "boolop",
        "cmpop",
        "excepthandler",
        "expr",
        "expr_context",
        "mod",
        "operator",
        "pattern",
        "slice",
        "stmt",
        "type_ignore",
        "type_param",
        "unaryop",
    }
)
NEVER_HASHED = frozenset(
    {"lineno", "col_offset", "end_lineno", "end_col_offset", "ctx", "type_comment"}
)
#: Fields added after Python 3.11; older interpreters lack them and read them as None.
LATER_FIELDS = frozenset({"type_params", "default_value"})


def test_field_table_covers_running_interpreter() -> None:
    assert len(FIELD_TABLE) == 104
    assert sum(1 for fields in FIELD_TABLE.values() if not fields) == 32
    node_classes = {
        name: value
        for name in dir(ast)
        if not name.startswith("_")
        and isinstance(value := getattr(ast, name), type)
        and issubclass(value, ast.AST)
    }
    unknown = set(node_classes) - set(FIELD_TABLE) - UNSUPPORTED_NODES
    unknown -= DEPRECATED_ALIASES | ABSTRACT_BASES
    assert not unknown, f"extend the pinned field table (new algorithm id?): {sorted(unknown)}"
    assert not UNSUPPORTED_NODES & set(FIELD_TABLE)
    for name, fields in FIELD_TABLE.items():
        node_class = node_classes.get(name)
        if node_class is None:
            continue
        hashed = tuple(
            field
            for field in node_class._fields
            if field not in NEVER_HASHED
            and (name, field) not in {("Constant", "kind"), ("Module", "type_ignores")}
        )
        assert fields[: len(hashed)] == hashed, name
        extra = set(fields[len(hashed) :])
        assert extra <= LATER_FIELDS, name
        if sys.version_info >= (3, 13):
            assert not extra, name


class FakeNode(ast.AST):
    _fields = ()


def _module(*statements: ast.stmt) -> ast.Module:
    return ast.Module(body=list(statements), type_ignores=[])


@pytest.mark.parametrize(
    "tree",
    [
        _module(ast.Expr(value=FakeNode())),
        _module(ast.Expr(value=ast.Constant(value=object()))),
        _module(ast.Expr(value=ast.Constant(value=(1, 2)))),
        _module(ast.Expr(value=ast.Name(id=b"x", ctx=ast.Load()))),
        _module(ast.Global(names=[True])),
        _module(ast.Expr(value=ast.JoinedStr(values="abc"))),
        _module(ast.Expr(value=ast.JoinedStr(values=[ast.JoinedStr(values="x")]))),
        _module(ast.Delete(targets="x")),
        _module(ast.Delete(targets=[ast.Tuple(elts="x", ctx=ast.Del())])),
    ],
)
def test_unknown_node_type_or_constant_is_unsupported(tree: ast.Module) -> None:
    with pytest.raises(UnsupportedSyntax):
        module_digest(tree, definition_digests(tree))


def test_definition_with_unknown_node_and_non_module_root_are_unsupported() -> None:
    tree = ast.parse("def f():\n    return 1\n")
    definition = tree.body[0]
    assert isinstance(definition, ast.FunctionDef)
    definition.body[0] = ast.Expr(value=FakeNode())
    with pytest.raises(UnsupportedSyntax):
        definition_digests(tree)
    with pytest.raises(UnsupportedSyntax):
        module_digest(ast.Expression(body=ast.Constant(1)), {})


def test_digest_layout_is_prefixed_and_hex() -> None:
    tree = ast.parse("def f():\n    pass\n")
    digests = definition_digests(tree)
    assert ALGORITHM_PREFIX == b"asca:python-ast/1\n"
    assert len(digests) == 1
    (value,) = digests.values()
    assert len(value) == 64 and set(value) <= set("0123456789abcdef")
    assert module_digest(tree, digests) != value


def test_serializer_is_iterative() -> None:
    expression = "(" * 190 + "x" + ")" * 190
    lines = ["def f(x):"]
    for depth in range(1, 91):
        lines.append("    " * depth + "if x:")
    lines.append("    " * 91 + f"return {expression}")
    tree = ast.parse("\n".join(lines) + "\n")
    limit = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(150)
        digests = definition_digests(tree)
        whole = module_digest(tree, digests)
    finally:
        sys.setrecursionlimit(limit)
    assert len(whole) == 64
    assert len(digests) == 1


# ---------------------------------------------------------------------- properties

NAMES = ("a", "b", "c")
OPERATORS = ("+", "-", "*", "//", "%")

Expr = tuple[object, ...]

leaf_strategy = st.one_of(
    st.tuples(st.just("name"), st.sampled_from(NAMES)),
    st.tuples(st.just("int"), st.integers(min_value=0, max_value=10**6)),
    st.tuples(st.just("str"), st.text(alphabet="abcxyz ", max_size=6)),
)
expression_strategy = st.recursive(
    leaf_strategy,
    lambda inner: st.one_of(
        st.tuples(st.just("binop"), st.sampled_from(OPERATORS), inner, inner),
        st.tuples(st.just("call"), st.lists(inner, max_size=3)),
    ),
    max_leaves=8,
)
statement_strategy = st.one_of(
    st.tuples(st.just("assign"), st.sampled_from(NAMES), expression_strategy),
    st.tuples(st.just("return"), expression_strategy),
    st.tuples(st.just("if"), expression_strategy, expression_strategy),
)
program_strategy = st.lists(statement_strategy, min_size=1, max_size=5)


def _space(rng: random.Random | None) -> str:
    return "" if rng is None else rng.choice(["", " ", "  "])


def _int(value: int, rng: random.Random | None) -> str:
    if rng is None:
        return str(value)
    choice = rng.randrange(5)
    if choice == 0:
        return hex(value)
    if choice == 1:
        return oct(value)
    if choice == 2:
        return bin(value)
    if choice == 3:
        return f"{value:_}"
    return str(value)


def _str(value: str, rng: random.Random | None) -> str:
    if rng is None:
        return repr(value)
    quote = rng.choice(["'", '"'])
    prefix = rng.choice(["", "u"])
    cut = rng.randrange(len(value) + 1)
    first, second = value[:cut], value[cut:]
    if rng.random() < 0.5:
        return f"{prefix}{quote}{value}{quote}"
    return f"{prefix}{quote}{first}{quote} {quote}{second}{quote}"


def render_expression(node: Expr, rng: random.Random | None) -> str:
    kind = node[0]
    if kind == "name":
        text = str(node[1])
    elif kind == "int":
        text = _int(int(node[1]), rng)
    elif kind == "str":
        text = _str(str(node[1]), rng)
    elif kind == "binop":
        left = render_expression(node[2], rng)
        right = render_expression(node[3], rng)
        text = f"({left}{_space(rng)}{node[1]}{_space(rng)}{right})"
    else:
        arguments = [render_expression(item, rng) for item in node[1]]
        trailing = "," if rng is not None and arguments and rng.random() < 0.5 else ""
        text = "g(" + ("," + _space(rng)).join(arguments) + trailing + ")"
    if rng is not None and rng.random() < 0.3:
        text = f"({_space(rng)}{text}{_space(rng)})"
    return text


def render_program(program: list[Expr], rng: random.Random | None) -> str:
    lines = ["def f(a, b, c):"]
    if rng is not None and rng.random() < 0.5:
        lines.append("    '''A docstring.'''")
    for statement in program:
        if rng is not None and rng.random() < 0.3:
            lines.append(rng.choice(["", "    # a comment", "# another"]))
        kind = statement[0]
        if kind == "assign":
            value = render_expression(statement[2], rng)
            lines.append(f"    {statement[1]}{_space(rng)}={_space(rng)}{value}")
        elif kind == "return":
            lines.append(f"    return {render_expression(statement[1], rng)}")
        else:
            test = render_expression(statement[1], rng)
            body = render_expression(statement[2], rng)
            lines.append(f"    if {test}{_space(rng)}:")
            lines.append(f"        a = {body}")
    return "\n".join(lines) + "\n"


@settings(max_examples=60, deadline=None)
@given(program_strategy, st.randoms(use_true_random=False))
def test_formatting_perturbations_keep_fingerprints(
    program: list[Expr], rng: random.Random
) -> None:
    assert fp(render_program(program, rng)) == fp(render_program(program, None))


def _mutate(node: Expr, path: list[int]) -> Expr:
    if not path:
        kind = node[0]
        if kind == "name":
            return ("name", NAMES[(NAMES.index(str(node[1])) + 1) % len(NAMES)])
        if kind == "int":
            return ("int", int(node[1]) + 1)
        if kind == "str":
            return ("str", str(node[1]) + "q")
        if kind == "binop":
            operator = OPERATORS[(OPERATORS.index(str(node[1])) + 1) % len(OPERATORS)]
            return ("binop", operator, node[2], node[3])
        return ("call", [*node[1], ("int", 0)])
    head, *rest = path
    children = list(node)
    if node[0] == "binop":
        index = 2 + head % 2
        children[index] = _mutate(node[index], rest)
        return tuple(children)
    if node[0] == "call" and node[1]:
        items = list(node[1])
        items[head % len(items)] = _mutate(items[head % len(items)], rest)
        return ("call", items)
    return _mutate(node, [])


@settings(max_examples=60, deadline=None)
@given(program_strategy, st.data())
def test_semantic_mutations_change_fingerprints(program: list[Expr], data: st.DataObject) -> None:
    position = data.draw(st.integers(min_value=0, max_value=len(program) - 1))
    path = data.draw(st.lists(st.integers(min_value=0, max_value=3), max_size=4))
    statement = program[position]
    mutated: Expr
    if statement[0] == "assign":
        mutated = (statement[0], statement[1], _mutate(statement[2], path))
    elif statement[0] == "return":
        mutated = (statement[0], _mutate(statement[1], path))
    else:
        mutated = (statement[0], _mutate(statement[1], path), statement[2])
    changed = [*program[:position], mutated, *program[position + 1 :]]
    assert fp(render_program(changed, None)) != fp(render_program(program, None))


def _repository_fingerprints(text: str) -> dict[str, str]:
    return fingerprints(text.encode("utf-8"))


@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.sampled_from(REPOSITORY_SOURCES))
def test_unparse_round_trip_on_repository_sources(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert _repository_fingerprints(ast.unparse(ast.parse(text))) == _repository_fingerprints(text)


def _comment_lines(text: str) -> list[int]:
    tokens = tokenize.generate_tokens(io.StringIO(text).readline)
    total = text.count("\n")
    return sorted(
        {
            token.start[0]
            for token in tokens
            if token.type in (tokenize.NEWLINE, tokenize.NL) and token.start[0] <= total
        }
    )


@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.sampled_from(REPOSITORY_SOURCES), st.randoms(use_true_random=False))
def test_comment_insertion_on_repository_sources(path: Path, rng: random.Random) -> None:
    text = path.read_text(encoding="utf-8")
    lines = text.split("\n")
    eligible = _comment_lines(text)
    chosen = rng.sample(eligible, k=min(len(eligible), rng.randrange(1, 20)))
    for line_number in chosen:
        lines[line_number - 1] += "  # inserted comment"
    assert _repository_fingerprints("\n".join(lines)) == _repository_fingerprints(text)


def test_repository_sources_exist() -> None:
    assert len(REPOSITORY_SOURCES) > 50


def _expression_module(value: ast.expr) -> str:
    tree = _module(ast.Expr(value=value))
    return module_digest(tree, definition_digests(tree))


def test_joined_strings_are_flattened_and_merged() -> None:
    formatted = ast.FormattedValue(value=ast.Name(id="x", ctx=ast.Load()), conversion=-1)
    nested = ast.JoinedStr(
        values=[
            ast.Constant(value="a"),
            ast.JoinedStr(values=[ast.Constant(value=""), ast.Constant(value="b")]),
            formatted,
            ast.Constant(value="c"),
            ast.Constant(value="d"),
        ]
    )
    flat = ast.JoinedStr(values=[ast.Constant(value="ab"), formatted, ast.Constant(value="cd")])
    assert _expression_module(nested) == _expression_module(flat)
    assert _expression_module(nested) != _expression_module(
        ast.JoinedStr(values=[ast.Constant(value="abc"), formatted, ast.Constant(value="d")])
    )


def test_import_from_without_level_equals_level_zero() -> None:
    def digest(level: int | None) -> str:
        statement = ast.ImportFrom(module="m", names=[ast.alias(name="x")], level=level)
        tree = _module(statement)
        return module_digest(tree, definition_digests(tree))

    assert digest(None) == digest(0) == fingerprints("from m import x\n")["__module__"]
    assert digest(None) != digest(1)
