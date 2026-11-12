"""Adversarial offline tests for the C5 authorization *design* contract."""

from __future__ import annotations

import json
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check_cern_web_authorization_contract.py"
CONTRACT = ROOT / "docs/security/cern-web-authorization-decision-contract.json"
REGISTER = ROOT / "docs/security/cern-web-oidc-evidence-register.json"
INTAKE = ROOT / "docs/security/cern-web-operator-intake-template.json"
NEGATIVE = ROOT / "docs/security/cern-web-negative-policy-cases.json"
ADR = ROOT / "docs/adr/0035-cern-web-authorization-decision-contract.md"
SPEC = spec_from_file_location("asca_c5_authorization_contract", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise ImportError("C5 offline authorization contract script unavailable")
review = module_from_spec(SPEC)
SPEC.loader.exec_module(review)


def record() -> dict[str, Any]:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


def store(tmp_path: Path, value: object) -> Path:
    target = tmp_path / "contract.json"
    target.write_text(json.dumps(value), encoding="utf-8")
    return target


def test_default_contract_is_deny_only_and_non_authoritative(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert review.main([]) == 0
    output = capsys.readouterr().out
    for item in (
        "MODE=OFFLINE_AUTHORIZATION_DECISION_CONTRACT",
        "ASCA_LOGIN=DISABLED",
        "ASCA_SESSION=DISABLED",
        "ROLE_AUTHORIZATION=DISABLED",
        "CHATLAS_ACCESS=DISABLED",
        "CONTRACT_STAGES=8",
        "RESOURCE_CLASSES=3",
        "SECURITY_GATES=10",
        "C4_NEGATIVE_CASES=20",
        "G1=BLOCKED",
        "G6=BLOCKED",
        "G7=BLOCKED",
        "RESULT=INDEPENDENT_REVIEW_REQUIRED_NO_GRANT",
    ):
        assert item in output
    assert "RESULT=APPROVED" not in output
    assert "RESULT=ALLOW" not in output


def test_contract_covers_all_security_gates_and_resource_boundaries() -> None:
    doc = record()
    assert doc["design_decision_values"] == ["DENY"]
    assert doc["runtime_authorization_enabled"] is False
    assert len(doc["stages"]) == 8
    assert {gate for item in doc["stages"] for gate in item["gates"]} == {
        f"G{i}" for i in range(1, 11)
    }
    assert {item["id"] for item in doc["resource_boundaries"]} == {
        "asca_workspace",
        "chatlas_read",
        "cern_gitlab_read",
    }
    assert {item["on_missing"] for item in doc["stages"]} == {"DENY"}
    assert {item["state"] for item in doc["resource_boundaries"]} == {"disabled"}
    assert review.validate_contract(CONTRACT) == (8, 3)


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(schema_version=True),
        lambda d: d.update(schema_version=2),
        lambda d: d.update(phase="1A.2.5C4"),
        lambda d: d.update(purpose="production_policy"),
        lambda d: d.update(runtime_authorization_enabled=True),
        lambda d: d.update(source_of_authority="operator"),
        lambda d: d.update(design_decision_values=["ALLOW"]),
        lambda d: d.update(design_decision_values=["DENY", "ALLOW"]),
        lambda d: d.update(extra="synthetic-secret"),
        lambda d: d.update(required_context_fields=[]),
        lambda d: d.update(required_decision_fields=["secret"]),
        lambda d: d.update(denial_reason_codes=["approved"]),
        lambda d: d.update(repository_gate_states={"G1": "approved"}),
        lambda d: d.update(prior_negative_cases_required=True),
        lambda d: d.update(prior_negative_cases_required=0),
        lambda d: d.update(result="READY"),
        lambda d: d.update(stages=[]),
        lambda d: d["stages"].reverse(),
        lambda d: d["stages"][0].update(on_missing="ALLOW"),
        lambda d: d["stages"][0].update(gates=["G8"]),
        lambda d: d["stages"][0].update(required_evidence="none"),
        lambda d: d["stages"][0].update(extra="synthetic-secret"),
        lambda d: d.update(resource_boundaries=[]),
        lambda d: d["resource_boundaries"][0].update(state="enabled"),
        lambda d: d["resource_boundaries"][1].update(required_rule="allow_all"),
        lambda d: d["resource_boundaries"].reverse(),
    ],
)
def test_forged_or_mutated_contracts_are_rejected_without_leaking(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], change: Any
) -> None:
    value = record()
    change(value)
    assert review.main(["--contract", str(store(tmp_path, value))]) == 2
    output = capsys.readouterr().out
    assert "RESULT=INVALID_OFFLINE_AUTHORIZATION_CONTRACT" in output
    assert str(tmp_path) not in output
    assert "synthetic-secret" not in output
    assert "ASCA_SESSION=DISABLED" in output


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":1,"schema_version":1}',
        b'{"stages":[{"id":"x","id":"y"}]}',
        b'{"schema_version":NaN}',
        b'{"schema_version":Infinity}',
        b"synthetic-secret",
        b"\xff\xfe\x00",
        b" " * 16385,
    ],
)
def test_corrupt_ambiguous_and_oversized_files_are_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], payload: bytes
) -> None:
    path = tmp_path / "invalid.json"
    path.write_bytes(payload)
    assert review.main(["--contract", str(path)]) == 2
    output = capsys.readouterr().out
    assert "RESULT=INVALID_OFFLINE_AUTHORIZATION_CONTRACT" in output
    assert "synthetic-secret" not in output


def test_symlink_directory_and_missing_files_are_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = store(tmp_path, record())
    link = tmp_path / "symlink.json"
    link.symlink_to(target)
    for path in (link, tmp_path, tmp_path / "missing.json"):
        assert review.main(["--contract", str(path)]) == 2
    output = capsys.readouterr().out
    assert output.count("RESULT=INVALID_OFFLINE_AUTHORIZATION_CONTRACT") == 3
    assert str(tmp_path) not in output


def test_c2_c3_c4_snapshots_are_still_blocked() -> None:
    assert review.validate_prior_snapshot() == 20
    assert "script evaluates a real user" in ADR.read_text(encoding="utf-8")
    source = SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("import requests", "import urllib", "import socket", "import webbrowser"):
        assert forbidden not in source


@pytest.mark.parametrize(
    ("filename", "change"),
    [
        ("register", lambda d: d.update(web_client_registered=True)),
        ("register", lambda d: d.update(positive_assurance_attested=True)),
        ("register", lambda d: d["gates"][0].update(state="approved")),
        ("intake", lambda d: d["gates"][0].update(status="submitted_for_review")),
        ("negative", lambda d: d["cases"][0].update(expected_decision="ALLOW")),
        ("negative", lambda d: d.update(authorization_enabled=True)),
        ("negative", lambda d: d.update(cases=[])),
    ],
)
def test_forged_prior_snapshots_are_not_promoted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str, change: Any
) -> None:
    sources = {
        "register": (REGISTER, "_REGISTER"),
        "intake": (INTAKE, "_INTAKE"),
        "negative": (NEGATIVE, "_C4_CASES"),
    }
    original, attribute = sources[filename]
    value = json.loads(original.read_text(encoding="utf-8"))
    change(value)
    monkeypatch.setattr(review, attribute, store(tmp_path, value))
    with pytest.raises(review.ContractReviewError):
        review.validate_prior_snapshot()
