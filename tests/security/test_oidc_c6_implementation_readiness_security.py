"""Offline adversarial tests for C6 implementation-readiness traceability."""

from __future__ import annotations

import json
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check_cern_web_implementation_readiness.py"
MATRIX = ROOT / "docs/security/cern-web-implementation-readiness-matrix.json"
ADR = ROOT / "docs/adr/0036-cern-web-implementation-readiness-boundary.md"
REVIEW = ROOT / "docs/security/cern-web-implementation-readiness-review.md"
SPEC = spec_from_file_location("asca_c6_offline_implementation_readiness", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise ImportError("C6 offline implementation-readiness script not found")
readiness = module_from_spec(SPEC)
SPEC.loader.exec_module(readiness)


def matrix() -> dict[str, Any]:
    return json.loads(MATRIX.read_text(encoding="utf-8"))


def store(tmp_path: Path, payload: object) -> Path:
    target = tmp_path / "candidate.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def test_default_matrix_requires_external_review(capsys: pytest.CaptureFixture[str]) -> None:
    assert readiness.main([]) == 0
    output = capsys.readouterr().out
    for label in (
        "MODE=OFFLINE_IMPLEMENTATION_READINESS_TRACEABILITY",
        "ASCA_LOGIN=DISABLED",
        "ASCA_SESSION=DISABLED",
        "ROLE_AUTHORIZATION=DISABLED",
        "CHATLAS_ACCESS=DISABLED",
        "EVIDENCE_SCOPE=REPOSITORY_SNAPSHOT_ONLY",
        "SECURITY_GATES=10",
        "BLOCKED_GATES=10",
        "OFFLINE_PREPARATION_ITEMS=10",
        "C5_CONTRACT_STAGES=8",
        "RESOURCE_CLASSES=3",
        "C4_NEGATIVE_CASES=20",
        "G1=BLOCKED",
        "G6=BLOCKED",
        "G7=BLOCKED",
        "RESULT=IMPLEMENTATION_REVIEW_REQUIRED_NO_GRANT",
    ):
        assert label in output
    assert "RESULT=APPROVED" not in output
    assert "RESULT=ALLOW" not in output


def test_all_ten_gates_are_blocked_with_separate_proof() -> None:
    doc = matrix()
    assert readiness.validate_matrix(MATRIX) == 10
    assert [item["gate"] for item in doc["work_items"]] == list(readiness.GATES)
    assert [item["snapshot_state"] for item in doc["work_items"]] == list(readiness.STATES)
    assert [item["evidence_owner_role"] for item in doc["work_items"]] == list(readiness.OWNERS)
    assert {item["readiness"] for item in doc["work_items"]} == {"blocked"}
    assert all(item["offline_preparation"] for item in doc["work_items"])
    assert all(item["external_proof_required"] for item in doc["work_items"])
    assert all("offline_unit" in item["verification_methods"] for item in doc["work_items"])
    assert doc["ready_for_deployment"] is False
    assert doc["runtime_authorization_enabled"] is False
    assert readiness.validate_prior_contracts() == (8, 3, 20)


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(schema_version=True),
        lambda d: d.update(schema_version=2),
        lambda d: d.update(phase="1A.2.5C5"),
        lambda d: d.update(purpose="production_readiness"),
        lambda d: d.update(production_implementation_approved=True),
        lambda d: d.update(live_evidence_attested=True),
        lambda d: d.update(runtime_login_enabled=True),
        lambda d: d.update(runtime_authorization_enabled=True),
        lambda d: d.update(ready_for_deployment=True),
        lambda d: d.update(source_of_authority="operator_self_attestation"),
        lambda d: d.update(resource_boundaries=["chatlas_read"]),
        lambda d: d.update(contract_stage_count=9),
        lambda d: d.update(c4_negative_cases=19),
        lambda d: d.update(result="APPROVED"),
        lambda d: d.update(extra="synthetic-secret"),
        lambda d: d.update(work_items=[]),
        lambda d: d["work_items"].reverse(),
        lambda d: d["work_items"][0].update(gate="G7"),
        lambda d: d["work_items"][0].update(snapshot_state="approved"),
        lambda d: d["work_items"][0].update(evidence_owner_role="user"),
        lambda d: d["work_items"][0].update(external_proof_required="not needed"),
        lambda d: d["work_items"][0].update(offline_preparation="skip verification"),
        lambda d: d["work_items"][0].update(verification_methods=[]),
        lambda d: d["work_items"][0].update(readiness="ready"),
        lambda d: d["work_items"][0].update(extra="synthetic-secret"),
    ],
)
def test_tampered_plans_are_rejected_without_leaking(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], change: Any
) -> None:
    doc = matrix()
    change(doc)
    assert readiness.main(["--matrix", str(store(tmp_path, doc))]) == 2
    output = capsys.readouterr().out
    assert "RESULT=INVALID_IMPLEMENTATION_READINESS_REQUIREMENTS" in output
    assert "synthetic-secret" not in output
    assert str(tmp_path) not in output
    assert "ROLE_AUTHORIZATION=DISABLED" in output


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":1,"schema_version":1}',
        b'{"work_items":[{"gate":"G1","gate":"G2"}]}',
        b'{"schema_version":NaN}',
        b'{"schema_version":Infinity}',
        b"synthetic-secret",
        b"\xff\xfe\x00",
        b" " * 16385,
    ],
)
def test_ambiguous_oversized_and_invalid_bytes_are_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], payload: bytes
) -> None:
    target = tmp_path / "malformed.json"
    target.write_bytes(payload)
    assert readiness.main(["--matrix", str(target)]) == 2
    output = capsys.readouterr().out
    assert "RESULT=INVALID_IMPLEMENTATION_READINESS_REQUIREMENTS" in output
    assert "synthetic-secret" not in output


def test_missing_symlink_and_directory_are_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = MATRIX
    link = tmp_path / "linked.json"
    link.symlink_to(target)
    for path in (link, tmp_path, tmp_path / "missing.json"):
        assert readiness.main(["--matrix", str(path)]) == 2
    output = capsys.readouterr().out
    assert output.count("RESULT=INVALID_IMPLEMENTATION_READINESS_REQUIREMENTS") == 3
    assert str(target) not in output


@pytest.mark.parametrize(
    ("source", "change"),
    [
        ("REGISTER", lambda d: d.update(web_client_registered=True)),
        ("REGISTER", lambda d: d["gates"][5].update(state="approved")),
        ("REGISTER", lambda d: d["gates"][0].update(id="G8")),
        ("INTAKE", lambda d: d["gates"][0].update(status="submitted_for_review")),
        ("NEGATIVE", lambda d: d["cases"][0].update(expected_decision="ALLOW")),
        ("NEGATIVE", lambda d: d["cases"].reverse()),
        ("CONTRACT", lambda d: d["resource_boundaries"][0].update(state="enabled")),
        ("CONTRACT", lambda d: d["stages"][0].update(on_missing="ALLOW")),
        ("CONTRACT", lambda d: d.update(design_decision_values=["ALLOW"])),
    ],
)
def test_forged_prior_contracts_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str, change: Any
) -> None:
    current = getattr(readiness, source)
    doc = json.loads(current.read_text(encoding="utf-8"))
    change(doc)
    monkeypatch.setattr(readiness, source, store(tmp_path, doc))
    with pytest.raises(readiness.ReadinessError):
        readiness.validate_prior_contracts()


def test_docs_preserve_non_authoritative_boundary() -> None:
    adr = ADR.read_text(encoding="utf-8")
    review = REVIEW.read_text(encoding="utf-8")
    source = SCRIPT.read_text(encoding="utf-8")
    assert "not an implementation readiness approval" in adr
    assert "independently reviewed" in review
    assert "RESULT=IMPLEMENTATION_REVIEW_REQUIRED_NO_GRANT" in source
    for forbidden in ("import requests", "import urllib", "import socket", "import webbrowser"):
        assert forbidden not in source
