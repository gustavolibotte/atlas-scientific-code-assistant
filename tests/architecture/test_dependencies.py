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
