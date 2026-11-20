"""Static architecture guard: domain/application cannot depend on infrastructure or API."""

import ast
import re
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
    "httpx2",
    "httpcore",
    "httpcore2",
    "mcp_types",
    "anyio",
    "defusedxml",
    "truststore",
    "sse_starlette",
    "jwt",
    "tomllib",
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
PURE_LAYER_FORBIDDEN_MODULES = (
    "ast",
    "tokenize",
    "os",
    "pathlib",
    "socket",
    "ssl",
    "subprocess",
    "urllib.request",
    "http.client",
    "tomllib",
)
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


KNOWLEDGE = ROOT / "infrastructure" / "knowledge"
KNOWLEDGE_ALLOWED = (
    "asca.domain",
    "asca.application",
    "asca.infrastructure.knowledge",
    "asca.infrastructure.indexing.filesystem",
    "pydantic",
    "httpx2",
    "defusedxml",
    "mcp",
    "mcp_types",
)
MCP_MODULES = frozenset({"mcp_client.py", "chatlas_probe.py"})
DEFUSEDXML_MODULES = frozenset({"arxiv.py", "recording.py"})
XML_STDLIB_MODULES = ("xml.etree", "xml.dom", "xml.sax", "lxml")
KNOWLEDGE_FORBIDDEN_MODULES = (
    "pickle",
    "marshal",
    "ctypes",
    "importlib",
    "webbrowser",
    "getpass",
    "http.cookiejar",
    "sqlite3",
)
DECLARED_THIRD_PARTY = frozenset(
    {
        "alembic",
        "cryptography",
        "fastapi",
        "pydantic",
        "pydantic_settings",
        "sqlalchemy",
        "starlette",
        "uvicorn",
        "httpx2",
        "mcp",
        "mcp_types",
        "defusedxml",
    }
)
CREDENTIAL_FIELD_RE = re.compile(
    r"(?i)token|secret|password|cookie|authorization|bearer|credential|header"
)


def _knowledge_allowed(module: str) -> bool:
    return _is_stdlib(module) or module == "asca" or _within(module, KNOWLEDGE_ALLOWED)


def knowledge_violations(path: Path) -> list[str]:
    """Import-rule violations of one module under ``infrastructure/knowledge``."""
    found: list[str] = []
    for module in imports(path):
        if not _knowledge_allowed(module):
            found.append(f"not allowed: {module}")
        if _within(module, ("mcp", "mcp_types")) and path.name not in MCP_MODULES:
            found.append(f"mcp outside the MCP client: {module}")
        if _within(module, ("defusedxml",)) and path.name not in DEFUSEDXML_MODULES:
            found.append(f"defusedxml outside the XML adapters: {module}")
        if path.name == "mcp_stdio_guard.py" and not _is_stdlib(module):
            found.append(f"the stdio guard imports {module}")
    return found


def test_knowledge_adapters_import_allowlist() -> None:
    modules = sorted(KNOWLEDGE.glob("*.py"))
    assert modules, "the knowledge adapters must exist"
    for path in modules:
        assert not knowledge_violations(path), f"{path}: {knowledge_violations(path)}"


def test_src_never_imports_the_mcp_server_side() -> None:
    for path in ROOT.rglob("*.py"):
        for module in imports(path):
            assert not _within(module, ("mcp.server",)), f"{path} imports {module}"


def test_src_never_imports_httpx() -> None:
    for path in ROOT.rglob("*.py"):
        for module in imports(path):
            assert not _within(module, ("httpx",)), f"{path} imports {module}"


def third_party_roots(path: Path) -> set[str]:
    roots = {module.split(".")[0] for module in imports(path)}
    return {root for root in roots if root != "asca" and root not in STDLIB}


def test_src_third_party_imports_are_declared() -> None:
    for path in ROOT.rglob("*.py"):
        undeclared = third_party_roots(path) - DECLARED_THIRD_PARTY
        assert not undeclared, f"{path} imports undeclared packages {sorted(undeclared)}"


def xml_violations(path: Path) -> set[str]:
    allowed_stdlib = {"xml.etree.ElementTree"} if path.name == "recording.py" else set()
    return {
        module
        for module in imports(path)
        if _within(module, XML_STDLIB_MODULES) and module not in allowed_stdlib
    }


def test_xml_parsing_only_through_defusedxml() -> None:
    for path in KNOWLEDGE.glob("*.py"):
        assert not xml_violations(path), f"{path} imports {sorted(xml_violations(path))}"


def execution_violations(path: Path) -> set[str]:
    found = {f"call:{name}" for name in forbidden_calls(path)}
    for module in imports(path):
        if _within(module, KNOWLEDGE_FORBIDDEN_MODULES):
            found.add(module)
        if _within(module, ("subprocess",)) and path.name != "mcp_stdio_guard.py":
            found.add(module)
    return found


def test_knowledge_never_executes_code() -> None:
    for path in KNOWLEDGE.glob("*.py"):
        assert not execution_violations(path), f"{path}: {sorted(execution_violations(path))}"


def credential_fields(path: Path) -> set[str]:
    """Annotated class-body field names that look like credential carriers."""
    source = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(source):
        if not isinstance(node, ast.ClassDef):
            continue
        for item in node.body:
            if (
                isinstance(item, ast.AnnAssign)
                and isinstance(item.target, ast.Name)
                and CREDENTIAL_FIELD_RE.search(item.target.id)
            ):
                found.add(f"{node.name}.{item.target.id}")
    return found


def test_no_credential_fields_in_application() -> None:
    paths = [*sorted((ROOT / "application" / "knowledge").glob("*.py"))]
    paths.append(ROOT / "application" / "ports.py")
    assert len(paths) > 2
    for path in paths:
        assert not credential_fields(path), f"{path}: {sorted(credential_fields(path))}"


def prompt_violations(path: Path) -> set[str]:
    source = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = {
        "input"
        for node in ast.walk(source)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "input"
    }
    found |= {module for module in imports(path) if _within(module, ("getpass",))}
    return found


def test_knowledge_cli_never_prompts() -> None:
    for path in KNOWLEDGE.glob("*.py"):
        assert not prompt_violations(path), f"{path} prompts: {sorted(prompt_violations(path))}"


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
    assert _within("httpx2", FORBIDDEN) and _within("mcp_types", FORBIDDEN)
    assert _within("tomllib", FORBIDDEN) and _within("jwt.algorithms", FORBIDDEN)
    assert _within("urllib.request", PURE_LAYER_FORBIDDEN_MODULES)
    assert not _within("urllib.parse", PURE_LAYER_FORBIDDEN_MODULES)


def test_knowledge_guards_detect_violations(tmp_path: Path) -> None:
    def sample(name: str, text: str) -> Path:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return path

    bad_imports = sample(
        "inspire.py",
        "import mcp\nimport defusedxml\nimport sqlalchemy\nfrom asca.api import main\n",
    )
    assert sorted(knowledge_violations(bad_imports)) == [
        "defusedxml outside the XML adapters: defusedxml",
        "mcp outside the MCP client: mcp",
        "not allowed: asca.api",
        "not allowed: sqlalchemy",
    ]
    good = sample("mcp_client.py", "import asca\nimport mcp\nimport httpx2\nimport pydantic\n")
    assert knowledge_violations(good) == []
    guard = sample("mcp_stdio_guard.py", "import subprocess\nimport asca.domain\n")
    assert knowledge_violations(guard) == ["the stdio guard imports asca.domain"]
    assert execution_violations(guard) == set()
    executing = sample(
        "local.py", "import pickle\nimport subprocess\nimport importlib.util\neval('1')\n"
    )
    assert execution_violations(executing) == {
        "pickle",
        "subprocess",
        "importlib.util",
        "call:eval",
    }
    xml = sample("arxiv.py", "import xml.etree.ElementTree\nimport lxml.etree\n")
    assert xml_violations(xml) == {"xml.etree.ElementTree", "lxml.etree"}
    recording = sample("recording.py", "import xml.etree.ElementTree\nimport xml.dom\n")
    assert xml_violations(recording) == {"xml.dom"}
    undeclared = sample("any.py", "import requests\nimport httpx2\nimport os\nimport asca\n")
    assert third_party_roots(undeclared) - DECLARED_THIRD_PARTY == {"requests"}
    fields = sample(
        "models.py",
        "class A:\n    auth_header: str\n    api_Token: str\n    title: str\n    x = 1\n",
    )
    assert credential_fields(fields) == {"A.auth_header", "A.api_Token"}
    prompts = sample("cli.py", "import getpass\nx = input('token? ')\nprint('input')\n")
    assert prompt_violations(prompts) == {"input", "getpass"}
    assert not _within("httpx2", ("httpx",))
