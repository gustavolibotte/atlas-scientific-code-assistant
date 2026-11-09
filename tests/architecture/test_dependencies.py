"""Static architecture guard: domain/application cannot depend on infrastructure or API."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "asca"
FORBIDDEN = (
    "asca.api",
    "asca.infrastructure",
    "fastapi",
    "sqlalchemy",
    "requests",
    "httpx",
    "mcp",
    "langchain",
)


def imports(path: Path) -> set[str]:
    source = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(source):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_domain_and_application_respect_direction() -> None:
    for folder in (ROOT / "domain", ROOT / "application"):
        for path in folder.rglob("*.py"):
            for module in imports(path):
                forbidden = any(
                    module == name or module.startswith(name + ".") for name in FORBIDDEN
                )
                assert not forbidden, f"Forbidden dependency {module} in {path}"
