"""Golden values of fingerprint algorithm ``python-ast/1`` (spec section 3.8, ADR 0039).

Any change here needs a new algorithm id. The corpora use the ``.pysrc`` extension so
that ``compileall`` and ruff never touch them (the 3.12 and 3.13 corpora use syntax the
older interpreters reject).
"""

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from asca.application.ports import DEFAULT_INDEX_LIMITS
from asca.domain.provenance import FingerprintAlgorithm
from asca.infrastructure.indexing.python_symbols import PythonAstExtractor

pytestmark = pytest.mark.contract

GOLDEN = Path(__file__).parent / "fingerprint_golden" / "python_ast_1"

REFERENCE_VECTORS = [
    ("", "__module__", "e6d4228a801836644b1c293d8368d762b122f93ca36c0c5d31464c15329dd87a"),
    ("x = 1\n", "__module__", "911fd30674d2bb8303fa0af977acacfc0b277f4ff7456a77b56ade4f3f65f831"),
    (
        "def f(n):\n    return f(n - 1)\n",
        "f",
        "033d84e47ae2688fbbf50e046836970fe47e6e79c1e03fd7ab4ee75d4ed4e58f",
    ),
    (
        "def f():\n    pass\n",
        "f",
        "f78d9a4780ac639dc862ff34fdafe0fbe9caaf36f5661cb5de39cd45d354492c",
    ),
]

CORPUS = {
    "Fit": ("class", "781ab4d372af36c19ab3ba4c2cfdb14c51995a318fb26a29962f2e85f72b221c"),
    "Fit.Inner": ("class", "dd923ce0f93b4519c2f455cad7423d15a88dd910d647d2a7ad47c81375210b9f"),
    "Fit.Inner.m": ("method", "270a9bf6a859b1b464407dd5937bf8237881e64257f1a9e9776dce71cdaf090d"),
    "Fit.__init__": ("method", "5667fca6a623c3d031859bd3fe875ade88939a1499b6cfd77e826be353da146f"),
    "Fit.value": ("method", "1ca788ba8bdc27623734b749e2ac7d0088284729ea0b483f571741339557088a"),
    "__module__": ("module", "0fd9a113991eedd6dc3f829e766c1c60baf626b8d05cac18111064bd8c7cc0fc"),
    "estimate_amplitude": (
        "function",
        "7b57113c6b8e26b64a1d608beb6ef221d158ed38e5c376c3453475e11d436633",
    ),
    "fetch": ("function", "067507f4ef9ae44179f2cfed3de2cb2f41eff2625b17165b88b72291a948d4b4"),
    "helper": ("function", "5238ac3514e1a86c78ae731349641d2999c2a9d96792d6c1915a68e21489e746"),
}


def _expected() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((GOLDEN / "expected.json").read_text(encoding="utf-8"))
    return loaded


def _fingerprints(data: bytes) -> dict[str, tuple[str, str]]:
    extraction = PythonAstExtractor().extract(data, DEFAULT_INDEX_LIMITS)
    assert extraction.issue is None
    return {
        symbol.qualified_name: (symbol.kind.value, symbol.fingerprint)
        for symbol in extraction.symbols
    }


def _golden(section: str) -> dict[str, tuple[str, str]]:
    return {name: (entry["kind"], entry["sha256"]) for name, entry in _expected()[section].items()}


def test_expected_file_names_the_algorithm_and_the_spec_vectors() -> None:
    expected = _expected()
    assert expected["algorithm"] == FingerprintAlgorithm.PYTHON_AST_1.value
    assert [
        (item["source"], item["qualified_name"], item["sha256"])
        for item in expected["reference_vectors"]
    ] == REFERENCE_VECTORS
    assert _golden("corpus") == CORPUS


@pytest.mark.parametrize(("source", "qualified_name", "digest"), REFERENCE_VECTORS)
def test_reference_vectors(source: str, qualified_name: str, digest: str) -> None:
    assert _fingerprints(source.encode("utf-8"))[qualified_name][1] == digest


def test_corpus_matches_golden() -> None:
    data = (GOLDEN / "corpus.pysrc").read_bytes()
    assert _fingerprints(data) == CORPUS


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 and PEP 701 need 3.12")
def test_py312_corpus() -> None:
    data = (GOLDEN / "corpus_py312.pysrc").read_bytes()
    assert _fingerprints(data) == _golden("corpus_py312")


@pytest.mark.skipif(sys.version_info < (3, 13), reason="PEP 696 needs 3.13")
def test_py313_corpus() -> None:
    data = (GOLDEN / "corpus_py313.pysrc").read_bytes()
    assert _fingerprints(data) == _golden("corpus_py313")


def test_newer_corpora_are_syntax_errors_on_older_interpreters() -> None:
    extractor = PythonAstExtractor()
    for name, version in (("corpus_py312", (3, 12)), ("corpus_py313", (3, 13))):
        extraction = extractor.extract(
            (GOLDEN / f"{name}.pysrc").read_bytes(), DEFAULT_INDEX_LIMITS
        )
        if sys.version_info < version:
            assert extraction.issue is not None
            assert extraction.issue.value == "syntax_error"
        else:
            assert extraction.issue is None
