"""Static architecture guard: domain/application cannot depend on infrastructure or API."""

import ast
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.architecture

ROOT = Path(__file__).resolve().parents[2] / "src" / "asca"
FORBIDDEN = (
    "asca.api",
    "asca.infrastructure",
    "fastapi",
    "sqlalchemy",
    "alembic",
    "pydantic",
    "pydantic_settings",
    "starlette",
    "uvicorn",
    "jsonschema",
    "requests",
    "httpx",
    "mcp",
    "langchain",
)
STDLIB = frozenset(sys.stdlib_module_names)


def imports(path: Path) -> set[str]:
    source = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(source):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                raise AssertionError(f"Relative import in {path}")
            if node.module:
                modules.add(node.module)
    return modules


def _within(module: str, prefixes: tuple[str, ...]) -> bool:
    return any(module == name or module.startswith(name + ".") for name in prefixes)


def _is_stdlib(module: str) -> bool:
    return module.split(".")[0] in STDLIB


def _modules(folder: str) -> list[tuple[Path, str]]:
    return [(path, module) for path in (ROOT / folder).rglob("*.py") for module in imports(path)]


def test_domain_and_application_respect_direction() -> None:
    for folder in (ROOT / "domain", ROOT / "application"):
        for path in folder.rglob("*.py"):
            for module in imports(path):
                forbidden = _within(module, FORBIDDEN)
                assert not forbidden, f"Forbidden dependency {module} in {path}"


def test_domain_imports_only_the_standard_library_and_itself() -> None:
    for path, module in _modules("domain"):
        assert _is_stdlib(module) or _within(module, ("asca.domain",)), (
            f"Domain module {path} imports {module}"
        )


def test_application_imports_only_stdlib_domain_application_and_contracts() -> None:
    allowed = ("asca.domain", "asca.application", "asca.contracts")
    for path, module in _modules("application"):
        assert _is_stdlib(module) or _within(module, allowed), (
            f"Application module {path} imports {module}"
        )


def test_contracts_import_only_the_standard_library() -> None:
    for path, module in _modules("contracts"):
        assert _is_stdlib(module), f"Contracts module {path} imports {module}"


def test_api_never_touches_persistence_libraries() -> None:
    for path, module in _modules("api"):
        assert not _within(module, ("sqlalchemy", "alembic")), f"{path} imports {module}"


INDEXING_FORBIDDEN_MODULES = (
    "importlib",
    "runpy",
    "subprocess",
    "multiprocessing",
    "ctypes",
    "pickle",
    "marshal",
    "code",
    "codeop",
    "pkgutil",
    "socket",
)
EXTRACTOR_FORBIDDEN_MODULES = ("os", "pathlib", "io", "codecs", "tokenize")
PURE_LAYER_FORBIDDEN_MODULES = ("ast", "tokenize", "os", "pathlib")
FORBIDDEN_CALLS = frozenset({"exec", "eval", "compile", "__import__"})
EXTRACTOR_MODULES = ("python_fingerprint.py", "python_symbols.py")


def forbidden_calls(path: Path) -> set[str]:
    """Calls that could execute, compile or import code: ``exec(...)``, ``builtins.eval(...)``.

    ``re.compile`` and other attribute calls named ``compile`` on a non-builtins object are
    not code execution and are allowed.
    """
    source = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(source):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if isinstance(function, ast.Name) and function.id in FORBIDDEN_CALLS:
            found.add(function.id)
        elif isinstance(function, ast.Attribute) and function.attr in FORBIDDEN_CALLS:
            owner = function.value
            on_builtins = isinstance(owner, ast.Name) and owner.id in ("builtins", "__builtins__")
            if function.attr != "compile" or on_builtins:
                found.add(function.attr)
    return found


def test_indexing_adapters_import_only_stdlib_domain_and_application() -> None:
    allowed = ("asca.domain", "asca.application", "asca.infrastructure.indexing")
    modules = _modules("infrastructure/indexing")
    assert modules, "the indexing adapters must exist"
    for path, module in modules:
        assert _is_stdlib(module) or _within(module, allowed), (
            f"Indexing module {path} imports {module}"
        )


def test_indexing_adapters_never_import_execution_or_network_modules() -> None:
    for path, module in _modules("infrastructure/indexing"):
        assert not _within(module, INDEXING_FORBIDDEN_MODULES), f"{path} imports {module}"


def test_indexing_adapters_never_execute_compile_or_import_code() -> None:
    for path in (ROOT / "infrastructure" / "indexing").rglob("*.py"):
        assert not forbidden_calls(path), f"{path} calls {sorted(forbidden_calls(path))}"


def test_python_extractor_never_touches_files_or_codecs() -> None:
    folder = ROOT / "infrastructure" / "indexing"
    for name in EXTRACTOR_MODULES:
        path = folder / name
        for module in imports(path):
            assert not _within(module, EXTRACTOR_FORBIDDEN_MODULES), f"{path} imports {module}"


def test_domain_and_application_never_parse_code_or_touch_files() -> None:
    for folder in ("domain", "application"):
        for path, module in _modules(folder):
            assert not _within(module, PURE_LAYER_FORBIDDEN_MODULES), f"{path} imports {module}"


def test_guards_detect_violations(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text("import sqlalchemy\nfrom asca.domain import provenance\n", encoding="utf-8")
    assert imports(sample) == {"sqlalchemy", "asca.domain"}
    assert _within("sqlalchemy.orm", FORBIDDEN)
    assert not _is_stdlib("sqlalchemy")
    assert _is_stdlib("collections.abc")
    relative = tmp_path / "relative.py"
    relative.write_text("from . import x\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="Relative import"):
        imports(relative)
    calls = tmp_path / "calls.py"
    calls.write_text(
        "import builtins, re\n"
        "exec('1')\n"
        "builtins.eval('1')\n"
        "builtins.compile('1', 'f', 'eval')\n"
        "__import__('os')\n"
        "re.compile('x')\n"
        "print('compile')\n",
        encoding="utf-8",
    )
    assert forbidden_calls(calls) == {"exec", "eval", "compile", "__import__"}
    clean = tmp_path / "clean.py"
    clean.write_text("import re\nre.compile('x')\nlen('exec')\n", encoding="utf-8")
    assert forbidden_calls(clean) == set()
    assert _within("importlib.util", INDEXING_FORBIDDEN_MODULES)
    assert not _within("asca.domain.provenance.code", INDEXING_FORBIDDEN_MODULES)
    assert not _within("codecs", ("code",))
