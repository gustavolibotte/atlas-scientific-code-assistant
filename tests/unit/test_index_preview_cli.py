"""Read-only symbol index preview CLI: output shape, determinism and fixed failures."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from workspace_builders import write_tree

from asca.application.indexing import BuiltIndex, build_index
from asca.application.ports import DEFAULT_INDEX_LIMITS
from asca.application.provenance import SymbolDraft
from asca.domain.provenance import Language, SymbolKind
from asca.infrastructure.indexing.__main__ import _summary, main
from asca.infrastructure.indexing.filesystem import FilesystemWorkspaceReader
from asca.infrastructure.indexing.python_symbols import PythonAstExtractor

pytestmark = pytest.mark.unit

SOURCE_SECRET = "SOURCE_SECRET_CONSTANT_91c2"
TREE: dict[str, str | bytes] = {
    "pkg/__init__.py": "",
    "pkg/model.py": (
        '"""Module docstring."""\n'
        f"TOKEN = {SOURCE_SECRET!r}\n"
        "\n"
        "class Model:\n"
        f'    """{SOURCE_SECRET} in a docstring."""\n'
        "    def fit(self, data):\n"
        f"        return {SOURCE_SECRET!r} + data  # {SOURCE_SECRET}\n"
        "\n"
        "async def run():\n"
        "    pass\n"
    ),
    "pkg/broken.py": f"def broken(:\n    {SOURCE_SECRET}\n",
    "README.md": f"{SOURCE_SECRET}\n",
}
TOP_KEYS = {
    "algorithms",
    "files_indexed",
    "files_seen",
    "issues",
    "skipped_definitions",
    "skipped_entries",
    "source_digest",
    "symbols",
}


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    write_tree(root, TREE)
    return root


def test_preview_prints_one_compact_sorted_json_line(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _run(capsys, str(workspace))

    assert (code, err) == (0, "")
    assert out.endswith("\n")
    assert out.count("\n") == 1
    document = json.loads(out)
    assert (
        out == json.dumps(document, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n"
    )
    assert set(document) == TOP_KEYS
    assert document["algorithms"] == ["python-ast/1"]
    assert document["files_seen"] == 3
    assert document["files_indexed"] == 2
    assert document["skipped_entries"] == 1
    assert document["skipped_definitions"] == 0
    assert document["issues"] == [{"file_path": "pkg/broken.py", "kind": "syntax_error"}]
    symbols = document["symbols"]
    assert [(item["file_path"], item["qualified_name"], item["kind"]) for item in symbols] == [
        ("pkg/__init__.py", "__module__", "module"),
        ("pkg/model.py", "Model", "class"),
        ("pkg/model.py", "Model.fit", "method"),
        ("pkg/model.py", "__module__", "module"),
        ("pkg/model.py", "run", "function"),
    ]
    for item in symbols:
        assert set(item) == {"file_path", "fingerprint", "kind", "qualified_name", "span"}
        assert len(item["fingerprint"]) == 64
        start, end = item["span"]
        assert 1 <= start <= end
    spans = {
        item["qualified_name"]: item["span"]
        for item in symbols
        if item["file_path"] == "pkg/model.py" and item["kind"] != "module"
    }
    assert spans == {"Model": [4, 7], "Model.fit": [6, 7], "run": [9, 10]}


def test_preview_matches_build_index_and_is_stable(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = _run(capsys, str(workspace))
    second = _run(capsys, str(workspace))
    assert first == second

    extractor = PythonAstExtractor()
    snapshot = FilesystemWorkspaceReader(workspace).read(extractor.suffixes, DEFAULT_INDEX_LIMITS)
    built = build_index(snapshot, (extractor,), DEFAULT_INDEX_LIMITS)
    document = json.loads(first[1])
    assert document["source_digest"] == built.source_digest
    assert [item["fingerprint"] for item in document["symbols"]] == [
        draft.fingerprint for draft in built.drafts
    ]


def test_preview_never_prints_source_text_or_absolute_paths(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _run(capsys, str(workspace))
    assert code == 0
    for leaked in (SOURCE_SECRET, "docstring", "Module docstring", str(workspace), "ws/"):
        assert leaked not in out
        assert leaked not in err


def test_preview_escapes_non_ascii_paths(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_tree(tmp_path, {"caf\u00e9.py": "def f():\n    pass\n"})
    code, out, _ = _run(capsys, str(tmp_path))
    assert code == 0
    assert out.isascii()
    assert {item["file_path"] for item in json.loads(out)["symbols"]} == {"caf\u00e9.py"}


def test_an_empty_workspace_is_a_valid_preview(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _run(capsys, str(tmp_path))
    assert (code, err) == (0, "")
    document = json.loads(out)
    assert (document["files_seen"], document["symbols"], document["issues"]) == (0, [], [])


def test_byte_limits_are_passed_to_the_reader(
    workspace: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = _run(capsys, str(workspace), "--max-file-bytes", "64")
    assert code == 0
    assert {"file_path": "pkg/model.py", "kind": "too_large"} in json.loads(out)["issues"]


@pytest.mark.parametrize(
    ("option", "failure"),
    [
        ("--max-files", "max_files"),
        ("--max-total-bytes", "max_total_bytes"),
    ],
)
def test_a_limit_error_exits_2_with_a_fixed_message(
    workspace: Path, capsys: pytest.CaptureFixture[str], option: str, failure: str
) -> None:
    code, out, err = _run(capsys, str(workspace), option, "1")
    assert (code, out) == (2, "")
    assert err == f"asca-index: workspace indexing failed: {failure}\n"


def test_a_missing_root_exits_2_without_echoing_the_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "missing_secret_root"
    code, out, err = _run(capsys, str(missing))
    assert (code, out) == (2, "")
    assert err == "asca-index: workspace indexing failed: root_unavailable\n"
    assert "missing_secret_root" not in err


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["root", "--max-files", "0"],
        ["root", "--max-files", "abc"],
        ["root", "--max-file-bytes", "-5"],
        ["root", "--max-total-bytes", "\u0661"],
        ["root", "--unknown"],
        ["one", "two"],
    ],
)
def test_usage_errors_exit_2(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _run(capsys, *argv)
    assert (code, out) == (2, "")
    assert err.startswith("usage: asca-index")


def test_help_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run(capsys, "--help")
    assert code == 0
    assert "read-only" in out


def test_a_symbol_without_a_span_is_printed_with_a_null_span() -> None:
    draft = SymbolDraft(Language.PYTHON, SymbolKind.MODULE, "__module__", "m.py")
    built = BuiltIndex(
        drafts=(draft,),
        issues=(),
        source_digest="0" * 64,
        files_seen=1,
        files_indexed=1,
        skipped_definitions=0,
        skipped_entries=0,
    )
    summary = _summary(built, PythonAstExtractor())
    assert summary["symbols"] == [
        {
            "file_path": "m.py",
            "qualified_name": "__module__",
            "kind": "module",
            "span": None,
            "fingerprint": None,
        }
    ]


def test_the_module_entry_point_runs_the_preview(workspace: Path) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "asca.infrastructure.indexing", str(workspace)],
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )
    assert (completed.returncode, completed.stderr) == (0, "")
    assert json.loads(completed.stdout)["files_seen"] == 3
