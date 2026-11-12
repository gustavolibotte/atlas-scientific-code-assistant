"""Adversarial offline tests for deny-only CERN web policy requirements."""

from __future__ import annotations

import json
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check_cern_web_negative_policy.py"
CASES = ROOT / "docs/security/cern-web-negative-policy-cases.json"
ADR = ROOT / "docs/adr/0034-independent-evidence-review-and-negative-policy-spec.md"
PROTOCOL = ROOT / "docs/security/cern-web-independent-review-protocol.md"
REGISTER = ROOT / "docs/security/cern-web-oidc-evidence-register.json"
INTAKE = ROOT / "docs/security/cern-web-operator-intake-template.json"
SPEC = spec_from_file_location("asca_c4_offline_negative_policy", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise ImportError("Offline C4 policy requirements script is unavailable")
policy = module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


def cases() -> dict[str, Any]:
    return json.loads(CASES.read_text(encoding="utf-8"))


def store(tmp_path: Path, value: object) -> Path:
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_complete_negative_contract_does_not_grant_authority(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert policy.main([]) == 0
    output = capsys.readouterr().out
    assert "MODE=OFFLINE_NEGATIVE_POLICY_REQUIREMENTS" in output
    assert "EVIDENCE_SCOPE=REPOSITORY_SNAPSHOT_ONLY" in output
    assert "NEGATIVE_CASES=20" in output
    assert "RESULT=INDEPENDENT_REVIEW_REQUIRED_NO_GRANT" in output
    for gate in ("G1", "G6", "G7"):
        assert f"{gate}=BLOCKED" in output
    for capability in ("ASCA_LOGIN", "ASCA_SESSION", "ROLE_AUTHORIZATION", "CHATLAS_ACCESS"):
        assert f"{capability}=DISABLED" in output
    assert "RESULT=AUTHORIZED" not in output and "RESULT=APPROVED" not in output


def test_each_synthetic_requirement_is_deny_only() -> None:
    fixture = cases()
    assert len(fixture["cases"]) == len(policy.REQUIRED_CASES) == 20
    assert {case["id"] for case in fixture["cases"]} == set(policy.REQUIRED_CASES)
    assert {case["expected_decision"] for case in fixture["cases"]} == {"DENY"}
    assert fixture["authorization_enabled"] is False
    assert fixture["review_state"] == "independent_review_required"
    assert policy.validate_cases(CASES) == 20


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(schema_version=True),
        lambda d: d.update(schema_version=2),
        lambda d: d.update(phase="1A.2.5C3"),
        lambda d: d.update(purpose="production_authorization_policy"),
        lambda d: d.update(authorization_enabled=True),
        lambda d: d.update(review_state="approved"),
        lambda d: d.update(extra="synthetic-private-value"),
        lambda d: d.update(cases=[]),
        lambda d: d["cases"].reverse(),
        lambda d: d["cases"][0].update(id="unknown_case"),
        lambda d: d["cases"][0].update(id=True),
        lambda d: d["cases"][0].update(expected_decision="ALLOW"),
        lambda d: d["cases"][0].update(expected_decision=True),
        lambda d: d["cases"][0].update(violation="synthetic-private-value"),
        lambda d: d["cases"][0].update(gates=["G8"]),
        lambda d: d["cases"][0].update(extra="secret"),
        lambda d: d.update(cases=[*d["cases"][:-1], d["cases"][0]]),
    ],
)
def test_mutated_or_privilege_claiming_vectors_are_rejected(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    change: Any,
) -> None:
    candidate = cases()
    change(candidate)
    assert policy.main(["--cases", str(store(tmp_path, candidate))]) == 2
    output = capsys.readouterr().out
    assert "RESULT=INVALID_NEGATIVE_POLICY_REQUIREMENTS" in output
    assert "synthetic-private-value" not in output
    assert str(tmp_path) not in output
    assert "ASCA_SESSION=DISABLED" in output


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":1,"schema_version":1}',
        b'{"cases":[{"id":"A","id":"B"}]}',
        b'{"schema_version":NaN}',
        b'{"schema_version":Infinity}',
        b"synthetic-secret",
        b"\xff\xfe\x00",
        b" " * 16385,
    ],
)
def test_ambiguous_oversized_or_invalid_bytes_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], raw: bytes
) -> None:
    candidate = tmp_path / "bytes.json"
    candidate.write_bytes(raw)
    assert policy.main(["--cases", str(candidate)]) == 2
    output = capsys.readouterr().out
    assert "RESULT=INVALID_NEGATIVE_POLICY_REQUIREMENTS" in output
    assert "synthetic-secret" not in output


def test_missing_symlink_and_directory_are_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = store(tmp_path, cases())
    link = tmp_path / "symlink.json"
    link.symlink_to(target)
    for path in (link, tmp_path, tmp_path / "missing.json"):
        assert policy.main(["--cases", str(path)]) == 2
    output = capsys.readouterr().out
    assert output.count("RESULT=INVALID_NEGATIVE_POLICY_REQUIREMENTS") == 3
    assert str(target) not in output


def test_missing_live_evidence_cannot_be_mislabeled_verified() -> None:
    current = json.loads(REGISTER.read_text(encoding="utf-8"))
    gate_states = {item["id"]: item["state"] for item in current["gates"]}
    assert gate_states["G1"] == "not_attested"
    assert gate_states["G6"] == "not_attested"
    assert gate_states["G7"] == "not_implemented"
    intake = json.loads(INTAKE.read_text(encoding="utf-8"))
    assert {item["status"] for item in intake["gates"]} == {"not_supplied"}
    policy.validate_blocked_snapshot()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.update(web_client_registered=True),
        lambda d: d.update(asca_authorization_enabled=True),
        lambda d: d["gates"][0].update(state="approved"),
        lambda d: d["gates"][1].update(state="approved"),
        lambda d: d["gates"][5].update(state="approved"),
        lambda d: d["gates"][6].update(state="approved"),
        lambda d: d["gates"].append(d["gates"][0]),
    ],
)
def test_forged_release_metadata_is_not_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: Any
) -> None:
    register = json.loads(REGISTER.read_text(encoding="utf-8"))
    mutation(register)
    monkeypatch.setattr(policy, "_REGISTER", store(tmp_path, register))
    with pytest.raises(policy.OfflineRequirementError):
        policy.validate_blocked_snapshot()


def test_submitted_intake_is_not_automatically_reviewed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    intake = json.loads(INTAKE.read_text(encoding="utf-8"))
    intake["gates"][0].update(status="submitted_for_review", reference="EVIDENCE-1234")
    monkeypatch.setattr(policy, "_INTAKE", store(tmp_path, intake))
    with pytest.raises(policy.OfflineRequirementError):
        policy.validate_blocked_snapshot()


def test_forged_intake_header_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    intake = json.loads(INTAKE.read_text(encoding="utf-8"))
    intake["extra"] = "approved"
    monkeypatch.setattr(policy, "_INTAKE", store(tmp_path, intake))
    with pytest.raises(policy.OfflineRequirementError):
        policy.validate_blocked_snapshot()


def test_protocol_requires_independent_evidence_and_no_runtime_grant() -> None:
    adr = ADR.read_text(encoding="utf-8")
    protocol = PROTOCOL.read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")
    assert "A reviewer must not approve their own submission" in adr
    assert "A zero exit status" in adr
    assert "no production authorization engine" in adr
    assert "**Current answer:**" in protocol
    assert "RESULT=INDEPENDENT_REVIEW_REQUIRED_NO_GRANT" in script
    for forbidden in ("import requests", "import urllib", "import socket", "import webbrowser"):
        assert forbidden not in script
