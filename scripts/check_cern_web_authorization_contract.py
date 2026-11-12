#!/usr/bin/env python3
"""Validate C5 offline decision-contract requirements; never grant access."""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from typing import Final

_ROOT: Final = Path(__file__).resolve().parents[1]
_CONTRACT: Final = _ROOT / "docs/security/cern-web-authorization-decision-contract.json"
_REGISTER: Final = _ROOT / "docs/security/cern-web-oidc-evidence-register.json"
_INTAKE: Final = _ROOT / "docs/security/cern-web-operator-intake-template.json"
_C4_CASES: Final = _ROOT / "docs/security/cern-web-negative-policy-cases.json"
_MAX_BYTES: Final = 16384

STAGES: Final = (
    (
        "web_client_binding",
        ("G1", "G2"),
        "Server-owned exact HTTPS web-client registration and browser binding",
    ),
    (
        "trusted_oidc_transaction",
        ("G3", "G4"),
        "Cryptographic validation within an atomic single-use server transaction",
    ),
    (
        "application_scoped_role",
        ("G5",),
        "Active exact-client application role with reviewed provenance",
    ),
    (
        "positive_authentication_assurance",
        ("G6",),
        "Provider-approved positive MFA and LoA evidence with required freshness",
    ),
    (
        "active_server_session",
        ("G7",),
        "Bound non-revoked server session within idle and absolute expiry",
    ),
    (
        "resource_specific_permission",
        ("G8",),
        "Explicit resource action audience scope consent and permission",
    ),
    (
        "operational_freshness",
        ("G9",),
        "Active key revocation role refresh audit and incident controls",
    ),
    (
        "independent_release_validation",
        ("G10",),
        "Independent security review and deployment-specific gate verification",
    ),
)
RESOURCES: Final = (
    (
        "asca_workspace",
        "Explicit ASCA action policy; no implicit entitlement from CERN role",
    ),
    (
        "chatlas_read",
        "Independent chATLAS audience scope consent and resource-side authorization",
    ),
    (
        "cern_gitlab_read",
        "Independent CERN GitLab audience scope consent and resource-side authorization",
    ),
)
CONTEXT_FIELDS: Final = (
    "server_attested_subject",
    "exact_registered_web_client",
    "trusted_oidc_transaction",
    "reviewed_role_state",
    "provider_positive_assurance",
    "server_session_state",
    "requested_resource",
    "requested_action",
    "delegated_resource_authority",
    "deployment_security_attestations",
)
DECISION_FIELDS: Final = (
    "decision",
    "reason_code",
    "policy_revision",
    "resource",
    "action",
    "correlation_id",
)
DENIAL_CODES: Final = (
    "untrusted_identity",
    "unregistered_client",
    "invalid_transaction",
    "missing_role",
    "unverified_assurance",
    "invalid_session",
    "forbidden_resource",
    "stale_operations",
    "unreviewed_deployment",
    "unknown_action",
)


class ContractReviewError(ValueError):
    """Sanitized offline contract failure; never includes input contents."""


def _unique_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractReviewError("Invalid contract")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ContractReviewError("Invalid contract")


def _load(path: Path) -> object:
    """Read bounded regular JSON, rejecting terminal symlink and duplicate keys."""
    fd: int | None = None
    try:
        if path.is_symlink():
            raise ContractReviewError("Invalid contract")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        status = os.fstat(fd)
        if not stat.S_ISREG(status.st_mode) or status.st_size > _MAX_BYTES:
            raise ContractReviewError("Invalid contract")
        data = os.read(fd, _MAX_BYTES + 1)
        if not data or len(data) > _MAX_BYTES:
            raise ContractReviewError("Invalid contract")
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_members,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, TypeError, ValueError, OverflowError):
        raise ContractReviewError("Invalid contract") from None
    finally:
        if fd is not None:
            os.close(fd)


def validate_contract(path: Path) -> tuple[int, int]:
    """Check a static design artifact, not a real authorization request."""
    obj = _load(path)
    if type(obj) is not dict or set(obj) != {
        "schema_version",
        "phase",
        "purpose",
        "runtime_authorization_enabled",
        "source_of_authority",
        "design_decision_values",
        "required_context_fields",
        "required_decision_fields",
        "denial_reason_codes",
        "stages",
        "resource_boundaries",
        "repository_gate_states",
        "prior_negative_cases_required",
        "result",
    }:
        raise ContractReviewError("Invalid contract")
    if (
        type(obj["schema_version"]) is not int
        or obj["schema_version"] != 1
        or obj["phase"] != "1A.2.5C5"
        or obj["purpose"] != "offline_authorization_decision_contract_review"
        or obj["runtime_authorization_enabled"] is not False
        or obj["source_of_authority"] != "no_repository_authority"
        or obj["design_decision_values"] != ["DENY"]
        or obj["required_context_fields"] != list(CONTEXT_FIELDS)
        or obj["required_decision_fields"] != list(DECISION_FIELDS)
        or obj["denial_reason_codes"] != list(DENIAL_CODES)
        or obj["repository_gate_states"]
        != {"G1": "not_attested", "G6": "not_attested", "G7": "not_implemented"}
        or type(obj["prior_negative_cases_required"]) is not int
        or obj["prior_negative_cases_required"] != 20
        or obj["result"] != "INDEPENDENT_REVIEW_REQUIRED_NO_GRANT"
    ):
        raise ContractReviewError("Invalid contract")
    stages = obj["stages"]
    if type(stages) is not list or len(stages) != len(STAGES):
        raise ContractReviewError("Invalid contract")
    for index, item in enumerate(stages):
        stage_id, gates, condition = STAGES[index]
        if type(item) is not dict or item != {
            "id": stage_id,
            "gates": list(gates),
            "required_evidence": condition,
            "on_missing": "DENY",
        }:
            raise ContractReviewError("Invalid contract")
    resources = obj["resource_boundaries"]
    if type(resources) is not list or len(resources) != len(RESOURCES):
        raise ContractReviewError("Invalid contract")
    for index, item in enumerate(resources):
        name, rule = RESOURCES[index]
        if type(item) is not dict or item != {
            "id": name,
            "required_rule": rule,
            "state": "disabled",
        }:
            raise ContractReviewError("Invalid contract")
    covered = {gate for _, gates, _ in STAGES for gate in gates}
    if covered != {f"G{i}" for i in range(1, 11)}:
        raise ContractReviewError("Invalid contract")
    return len(stages), len(resources)


def validate_prior_snapshot() -> int:
    """Require C2/C3 release gates blocked and C4 DENY cases synthetic."""
    register, intake, negative = _load(_REGISTER), _load(_INTAKE), _load(_C4_CASES)
    if type(register) is not dict or type(intake) is not dict or type(negative) is not dict:
        raise ContractReviewError("Invalid contract")
    if register.get("review_kind") != "design_only" or any(
        register.get(name) is not False
        for name in (
            "web_client_registered",
            "positive_assurance_attested",
            "production_sessions_enabled",
            "asca_authorization_enabled",
            "chatlas_access_enabled",
        )
    ):
        raise ContractReviewError("Invalid contract")
    gates = register.get("gates")
    if type(gates) is not list or len(gates) != 10:
        raise ContractReviewError("Invalid contract")
    states: dict[str, str] = {}
    for gate in gates:
        if type(gate) is not dict:
            raise ContractReviewError("Invalid contract")
        key, state = gate.get("id"), gate.get("state")
        if type(key) is not str or type(state) is not str or key in states:
            raise ContractReviewError("Invalid contract")
        states[key] = state
    if set(states) != {f"G{i}" for i in range(1, 11)} or any(
        states.get(gate) != value
        for gate, value in (
            ("G1", "not_attested"),
            ("G6", "not_attested"),
            ("G7", "not_implemented"),
        )
    ):
        raise ContractReviewError("Invalid contract")
    if (
        type(intake.get("gates")) is not list
        or len(intake["gates"]) != 3
        or intake.get("record_type") != "non_authoritative_operator_intake"
    ):
        raise ContractReviewError("Invalid contract")
    for gate_id, entry in zip(("G1", "G6", "G7"), intake["gates"], strict=True):
        if type(entry) is not dict or entry != {
            "id": gate_id,
            "status": "not_supplied",
            "reference": None,
        }:
            raise ContractReviewError("Invalid contract")
    cases = negative.get("cases")
    if (
        negative.get("purpose") != "synthetic_negative_policy_requirements"
        or negative.get("authorization_enabled") is not False
        or negative.get("review_state") != "independent_review_required"
        or type(cases) is not list
        or len(cases) != 20
    ):
        raise ContractReviewError("Invalid contract")
    for case in cases:
        if (
            type(case) is not dict
            or set(case) != {"id", "violation", "expected_decision", "gates"}
            or case["expected_decision"] != "DENY"
            or type(case["gates"]) is not list
        ):
            raise ContractReviewError("Invalid contract")
    return len(cases)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--contract",
        type=Path,
        default=_CONTRACT,
        help="Offline versioned authorization design only, never real identities",
    )
    args = parser.parse_args(argv)
    print("MODE=OFFLINE_AUTHORIZATION_DECISION_CONTRACT")
    print("ASCA_LOGIN=DISABLED")
    print("ASCA_SESSION=DISABLED")
    print("ROLE_AUTHORIZATION=DISABLED")
    print("CHATLAS_ACCESS=DISABLED")
    try:
        stage_count, resource_count = validate_contract(args.contract)
        negative_count = validate_prior_snapshot()
    except ContractReviewError:
        print("RESULT=INVALID_OFFLINE_AUTHORIZATION_CONTRACT")
        return 2
    print(f"CONTRACT_STAGES={stage_count}")
    print(f"RESOURCE_CLASSES={resource_count}")
    print("SECURITY_GATES=10")
    print(f"C4_NEGATIVE_CASES={negative_count}")
    for gate_id in ("G1", "G6", "G7"):
        print(f"{gate_id}=BLOCKED")
    print("RESULT=INDEPENDENT_REVIEW_REQUIRED_NO_GRANT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
