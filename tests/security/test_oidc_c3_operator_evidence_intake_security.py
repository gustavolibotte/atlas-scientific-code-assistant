"""Offline, adversarial checks for non-authoritative CERN evidence intake."""

from __future__ import annotations

import json
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check_cern_web_operator_intake.py"
TEMPLATE = ROOT / "docs/security/cern-web-operator-intake-template.json"
ADR = ROOT / "docs/adr/0033-cern-web-operator-evidence-intake.md"
SPEC = spec_from_file_location("asca_cern_web_operator_intake", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise ImportError("Offline CERN evidence intake script is unavailable")
intake = module_from_spec(SPEC)
SPEC.loader.exec_module(intake)


def record() -> dict[str, Any]:
    return json.loads(TEMPLATE.read_text(encoding="utf-8"))


def store(tmp_path: Path, value: object) -> Path:
    destination = tmp_path / "candidate.json"
    destination.write_text(json.dumps(value), encoding="utf-8")
    return destination


def test_default_template_requires_review_and_does_not_enable_any_access(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert intake.main([]) == 0
    output = capsys.readouterr().out
    assert "RECORD=STRUCTURALLY_VALID_NON_AUTHORITATIVE" in output
    assert "RESULT=OPERATOR_REVIEW_REQUIRED" in output
    for gate in ("G1", "G6", "G7"):
        assert f"{gate}=NOT_SUPPLIED" in output
    for field in ("ASCA_LOGIN", "ASCA_SESSION", "ROLE_AUTHORIZATION", "CHATLAS_ACCESS"):
        assert f"{field}=DISABLED" in output
    assert "READY" not in output and "APPROVED" not in output


def test_all_submitted_references_are_still_unverified(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    doc = record()
    for index, gate in enumerate(doc["gates"]):
        gate["status"] = "submitted_for_review"
        gate["reference"] = f"EVIDENCE-{1234 + index}"
    local = store(tmp_path, doc)
    assert intake.main(["--record", str(local)]) == 0
    output = capsys.readouterr().out
    for gate in ("G1", "G6", "G7"):
        assert f"{gate}=SUBMITTED_UNVERIFIED" in output
    assert "RESULT=OPERATOR_REVIEW_REQUIRED" in output
    assert "EVIDENCE-" not in output
    assert "READY" not in output and "APPROVED" not in output


def test_mixed_states_are_not_a_grant(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    doc = record()
    doc["gates"][0] = {
        "id": "G1",
        "status": "submitted_for_review",
        "reference": "EVIDENCE-1234",
    }
    assert intake.main(["--record", str(store(tmp_path, doc))]) == 0
    output = capsys.readouterr().out
    assert "G1=SUBMITTED_UNVERIFIED" in output
    assert "G6=NOT_SUPPLIED" in output
    assert "G7=NOT_SUPPLIED" in output
    assert "ASCA_SESSION=DISABLED" in output


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(extra="synthetic-secret"),
        lambda d: d.update(schema_version=True),
        lambda d: d.update(schema_version=2),
        lambda d: d.update(record_type="release_approved"),
        lambda d: d.update(phase="1A.2.5C4"),
        lambda d: d.update(gates=[]),
        lambda d: d["gates"][0].update(id="G8"),
        lambda d: d["gates"][0].update(status="approved"),
        lambda d: d["gates"][0].update(status=True),
        lambda d: d["gates"][0].update(reference="EVIDENCE-1234"),
        lambda d: d["gates"][0].update(status="submitted_for_review"),
        lambda d: d["gates"][0].update(
            status="submitted_for_review",
            reference="https://example.invalid/secret",
        ),
        lambda d: d["gates"][0].update(
            status="submitted_for_review",
            reference="access_token=synthetic-private-token",
        ),
        lambda d: d["gates"][0].update(extra="synthetic-secret"),
        lambda d: d["gates"].reverse(),
        lambda d: d.update(gates=d["gates"] + [d["gates"][0]]),
    ],
)
def test_invalid_or_privilege_claiming_documents_are_rejected_without_leaking(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    change: Any,
) -> None:
    doc = record()
    change(doc)
    assert intake.main(["--record", str(store(tmp_path, doc))]) == 2
    output = capsys.readouterr().out
    assert "RESULT=INVALID_EVIDENCE_RECORD" in output
    assert "synthetic-secret" not in output
    assert "access_token" not in output
    assert "example.invalid" not in output
    assert str(tmp_path) not in output
    assert "ASCA_LOGIN=DISABLED" in output


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":1,"schema_version":1}',
        b'{"gates":[{"id":"G1","id":"G1"}]}',
        b'{"schema_version":NaN}',
        b'{"schema_version":Infinity}',
        b"not-json-and-secret=private-secret",
        b"\xff\xfe\x00",
        b" " * 4097,
    ],
)
def test_ambiguous_or_oversized_bytes_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], raw: bytes
) -> None:
    target = tmp_path / "invalid.json"
    target.write_bytes(raw)
    assert intake.main(["--record", str(target)]) == 2
    output = capsys.readouterr().out
    assert "RESULT=INVALID_EVIDENCE_RECORD" in output
    assert "private-secret" not in output


def test_symlink_and_directory_are_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = store(tmp_path, record())
    link = tmp_path / "linked.json"
    link.symlink_to(target)
    assert intake.main(["--record", str(link)]) == 2
    assert intake.main(["--record", str(tmp_path)]) == 2
    output = capsys.readouterr().out
    assert output.count("RESULT=INVALID_EVIDENCE_RECORD") == 2
    assert str(target) not in output


def test_absent_record_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert intake.main(["--record", str(tmp_path / "missing.json")]) == 2
    assert "RESULT=INVALID_EVIDENCE_RECORD" in capsys.readouterr().out


def test_no_offline_intake_path_grants_authority() -> None:
    contents = SCRIPT.read_text(encoding="utf-8")
    adr = ADR.read_text(encoding="utf-8")
    assert "OPERATOR_REVIEW_REQUIRED" in contents
    assert "INVALID_EVIDENCE_RECORD" in contents
    assert "no authenticated ASCA route/session" in adr
    assert "G1" in adr and "G6" in adr and "G7" in adr
    for forbidden in ("import requests", "import urllib", "import socket", "import webbrowser"):
        assert forbidden not in contents
