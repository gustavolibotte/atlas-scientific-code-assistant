#!/usr/bin/env python3
"""Validate C6 offline implementation-readiness planning, never grant access."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]
MATRIX: Final = ROOT / "docs/security/cern-web-implementation-readiness-matrix.json"
REGISTER: Final = ROOT / "docs/security/cern-web-oidc-evidence-register.json"
INTAKE: Final = ROOT / "docs/security/cern-web-operator-intake-template.json"
NEGATIVE: Final = ROOT / "docs/security/cern-web-negative-policy-cases.json"
CONTRACT: Final = ROOT / "docs/security/cern-web-authorization-decision-contract.json"
MAX_BYTES: Final = 16384
# Pin the exact static planning contract; no mutable user-supplied approval states.
MATRIX_SHA256: Final = "b4e1c02a825f343d04a8b6bdb29b33796aa0ea51f1bf8fca1ee40e14d48e5f5d"
GATES: Final = ("G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8", "G9", "G10")
STATES: Final = (
    "not_attested",
    "not_implemented",
    "diagnostic_only",
    "not_implemented",
    "diagnostic_only",
    "not_attested",
    "not_implemented",
    "not_attested",
    "not_implemented",
    "partial_offline",
)
OWNERS: Final = (
    "application_owner",
    "security_architect",
    "security_engineer",
    "security_engineer",
    "application_owner",
    "provider_and_security_reviewer",
    "security_architect",
    "resource_owner",
    "operations_owner",
    "independent_security_reviewer",
)
RESOURCES: Final = ("asca_workspace", "chatlas_read", "cern_gitlab_read")
STAGES: Final = (
    ("web_client_binding", ("G1", "G2")),
    ("trusted_oidc_transaction", ("G3", "G4")),
    ("application_scoped_role", ("G5",)),
    ("positive_authentication_assurance", ("G6",)),
    ("active_server_session", ("G7",)),
    ("resource_specific_permission", ("G8",)),
    ("operational_freshness", ("G9",)),
    ("independent_release_validation", ("G10",)),
)
C4_IDS: Final = (
    "diagnostic_role_claimed",
    "forged_checked_token",
    "mismatched_cern_issuer",
    "wrong_oidc_client",
    "wrong_application_role_scope",
    "missing_role",
    "revoked_role",
    "stale_role",
    "contradictory_role_claim",
    "missing_positive_assurance",
    "expired_assurance",
    "replayed_authorization_callback",
    "unbound_browser_callback",
    "expired_session",
    "revoked_session",
    "wrong_resource_audience",
    "missing_resource_scope",
    "unknown_protected_action",
    "unreviewed_operator_intake",
    "missing_deployment_gate",
)


class ReadinessError(ValueError):
    """Sanitized failure of an offline planning document, without source values."""


def _unique_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    members: dict[str, object] = {}
    for key, value in pairs:
        if key in members:
            raise ReadinessError("Invalid readiness requirements")
        members[key] = value
    return members


def _reject_constant(_value: str) -> None:
    raise ReadinessError("Invalid readiness requirements")


def _load(path: Path) -> tuple[object, bytes]:
    """Read bounded regular JSON without following a final path symlink."""
    descriptor: int | None = None
    try:
        if path.is_symlink():
            raise ReadinessError("Invalid readiness requirements")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_BYTES:
            raise ReadinessError("Invalid readiness requirements")
        payload = os.read(descriptor, MAX_BYTES + 1)
        if not payload or len(payload) > MAX_BYTES:
            raise ReadinessError("Invalid readiness requirements")
        parsed = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_members,
            parse_constant=_reject_constant,
        )
        return parsed, payload
    except (OSError, ValueError, TypeError, UnicodeError, OverflowError):
        raise ReadinessError("Invalid readiness requirements") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def validate_matrix(path: Path) -> int:
    """Check a fixed traceability artifact, not actual deployment readiness."""
    matrix, payload = _load(path)
    if hashlib.sha256(payload).hexdigest() != MATRIX_SHA256:
        raise ReadinessError("Invalid readiness requirements")
    if type(matrix) is not dict or set(matrix) != {
        "schema_version",
        "phase",
        "purpose",
        "production_implementation_approved",
        "live_evidence_attested",
        "runtime_login_enabled",
        "runtime_authorization_enabled",
        "ready_for_deployment",
        "source_of_authority",
        "resource_boundaries",
        "contract_stage_count",
        "c4_negative_cases",
        "work_items",
        "result",
    }:
        raise ReadinessError("Invalid readiness requirements")
    if (
        type(matrix["schema_version"]) is not int
        or matrix["schema_version"] != 1
        or matrix["phase"] != "1A.2.5C6"
        or matrix["purpose"] != "offline_implementation_readiness_traceability"
        or any(
            matrix[key] is not False
            for key in (
                "production_implementation_approved",
                "live_evidence_attested",
                "runtime_login_enabled",
                "runtime_authorization_enabled",
                "ready_for_deployment",
            )
        )
        or matrix["source_of_authority"] != "no_repository_authority"
        or matrix["resource_boundaries"] != list(RESOURCES)
        or type(matrix["contract_stage_count"]) is not int
        or matrix["contract_stage_count"] != len(STAGES)
        or type(matrix["c4_negative_cases"]) is not int
        or matrix["c4_negative_cases"] != len(C4_IDS)
        or matrix["result"] != "IMPLEMENTATION_REVIEW_REQUIRED_NO_GRANT"
    ):
        raise ReadinessError("Invalid readiness requirements")
    rows = matrix["work_items"]
    if type(rows) is not list or len(rows) != len(GATES):
        raise ReadinessError("Invalid readiness requirements")
    for row, gate, state, owner in zip(rows, GATES, STATES, OWNERS, strict=True):
        if (
            type(row) is not dict
            or set(row)
            != {
                "gate",
                "snapshot_state",
                "evidence_owner_role",
                "external_proof_required",
                "offline_preparation",
                "verification_methods",
                "readiness",
            }
            or row["gate"] != gate
            or row["snapshot_state"] != state
            or row["evidence_owner_role"] != owner
            or row["readiness"] != "blocked"
            or type(row["external_proof_required"]) is not str
            or not row["external_proof_required"]
            or type(row["offline_preparation"]) is not str
            or not row["offline_preparation"]
            or type(row["verification_methods"]) is not list
            or not row["verification_methods"]
            or row["verification_methods"][0] != "offline_unit"
        ):
            raise ReadinessError("Invalid readiness requirements")
    return len(rows)


def validate_prior_contracts() -> tuple[int, int, int]:
    """Check C2/C3/C4/C5 committed snapshots, not live provider evidence."""
    register, _ = _load(REGISTER)
    intake, _ = _load(INTAKE)
    negative, _ = _load(NEGATIVE)
    contract, _ = _load(CONTRACT)
    if any(type(doc) is not dict for doc in (register, intake, negative, contract)):
        raise ReadinessError("Invalid readiness requirements")
    if register.get("review_kind") != "design_only" or any(
        register.get(flag) is not False
        for flag in (
            "web_client_registered",
            "positive_assurance_attested",
            "production_sessions_enabled",
            "asca_authorization_enabled",
            "chatlas_access_enabled",
        )
    ):
        raise ReadinessError("Invalid readiness requirements")
    gates = register.get("gates")
    if type(gates) is not list or len(gates) != len(GATES):
        raise ReadinessError("Invalid readiness requirements")
    for row, gate_id, state in zip(gates, GATES, STATES, strict=True):
        if type(row) is not dict or row.get("id") != gate_id or row.get("state") != state:
            raise ReadinessError("Invalid readiness requirements")
    if (
        intake.get("record_type") != "non_authoritative_operator_intake"
        or intake.get("phase") != "1A.2.5C3"
        or type(intake.get("gates")) is not list
        or len(intake["gates"]) != 3
    ):
        raise ReadinessError("Invalid readiness requirements")
    for gate, row in zip(("G1", "G6", "G7"), intake["gates"], strict=True):
        if type(row) is not dict or row != {
            "id": gate,
            "status": "not_supplied",
            "reference": None,
        }:
            raise ReadinessError("Invalid readiness requirements")
    cases = negative.get("cases")
    if (
        negative.get("purpose") != "synthetic_negative_policy_requirements"
        or negative.get("authorization_enabled") is not False
        or type(cases) is not list
        or len(cases) != len(C4_IDS)
    ):
        raise ReadinessError("Invalid readiness requirements")
    for case, case_id in zip(cases, C4_IDS, strict=True):
        if (
            type(case) is not dict
            or case.get("id") != case_id
            or case.get("expected_decision") != "DENY"
        ):
            raise ReadinessError("Invalid readiness requirements")
    stages, resources = contract.get("stages"), contract.get("resource_boundaries")
    if (
        contract.get("purpose") != "offline_authorization_decision_contract_review"
        or contract.get("runtime_authorization_enabled") is not False
        or contract.get("design_decision_values") != ["DENY"]
        or contract.get("result") != "INDEPENDENT_REVIEW_REQUIRED_NO_GRANT"
        or type(stages) is not list
        or len(stages) != len(STAGES)
        or type(resources) is not list
        or len(resources) != len(RESOURCES)
    ):
        raise ReadinessError("Invalid readiness requirements")
    for stage, (stage_id, gate_ids) in zip(stages, STAGES, strict=True):
        if (
            type(stage) is not dict
            or stage.get("id") != stage_id
            or stage.get("gates") != list(gate_ids)
            or stage.get("on_missing") != "DENY"
        ):
            raise ReadinessError("Invalid readiness requirements")
    for resource, name in zip(resources, RESOURCES, strict=True):
        if (
            type(resource) is not dict
            or resource.get("id") != name
            or resource.get("state") != "disabled"
        ):
            raise ReadinessError("Invalid readiness requirements")
    return len(stages), len(resources), len(cases)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--matrix",
        type=Path,
        default=MATRIX,
        help="Non-secret offline planning matrix; not provider attestation",
    )
    args = parser.parse_args(argv)
    print("MODE=OFFLINE_IMPLEMENTATION_READINESS_TRACEABILITY")
    print("ASCA_LOGIN=DISABLED")
    print("ASCA_SESSION=DISABLED")
    print("ROLE_AUTHORIZATION=DISABLED")
    print("CHATLAS_ACCESS=DISABLED")
    print("EVIDENCE_SCOPE=REPOSITORY_SNAPSHOT_ONLY")
    try:
        gate_count = validate_matrix(args.matrix)
        stage_count, resource_count, negative_count = validate_prior_contracts()
    except ReadinessError:
        print("RESULT=INVALID_IMPLEMENTATION_READINESS_REQUIREMENTS")
        return 2
    print(f"SECURITY_GATES={gate_count}")
    print(f"BLOCKED_GATES={gate_count}")
    print(f"OFFLINE_PREPARATION_ITEMS={gate_count}")
    print(f"C5_CONTRACT_STAGES={stage_count}")
    print(f"RESOURCE_CLASSES={resource_count}")
    print(f"C4_NEGATIVE_CASES={negative_count}")
    for gate in ("G1", "G6", "G7"):
        print(f"{gate}=BLOCKED")
    print("RESULT=IMPLEMENTATION_REVIEW_REQUIRED_NO_GRANT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
