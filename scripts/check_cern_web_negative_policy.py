#!/usr/bin/env python3
"""Validate offline DENY-only CERN web policy requirements, not access rights.

Never verify actual operator evidence, grant permissions or print source records.
A zero exit status means a valid specification and blocked repository snapshot.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from typing import Final

_ROOT: Final = Path(__file__).resolve().parents[1]
_CASES: Final = _ROOT / "docs/security/cern-web-negative-policy-cases.json"
_REGISTER: Final = _ROOT / "docs/security/cern-web-oidc-evidence-register.json"
_INTAKE: Final = _ROOT / "docs/security/cern-web-operator-intake-template.json"
_MAX_BYTES: Final = 16384

# Exact, synthetic negative requirements. This is NOT an authorization policy.
REQUIRED_CASES: Final[dict[str, tuple[str, tuple[str, ...]]]] = {
    "diagnostic_role_claimed": ("Native diagnostic promoted to web authorization", ("G3", "G5")),
    "forged_checked_token": ("Forged checked-token wrapper", ("G3",)),
    "mismatched_cern_issuer": ("Issuer not pinned to approved CERN provider", ("G3",)),
    "wrong_oidc_client": ("Token intended for a different OIDC client", ("G1", "G3")),
    "wrong_application_role_scope": ("Role belongs to a different client", ("G5",)),
    "missing_role": ("Required application role is absent", ("G5",)),
    "revoked_role": ("Application role was revoked", ("G5", "G9")),
    "stale_role": ("Application role has not been revalidated", ("G5", "G9")),
    "contradictory_role_claim": ("Role conflicts with denial or assurance hints", ("G5", "G6")),
    "missing_positive_assurance": ("No provider-approved MFA/LoA proof", ("G6",)),
    "expired_assurance": ("Authentication assurance is stale", ("G6", "G7")),
    "replayed_authorization_callback": ("Authorization callback was consumed before", ("G2", "G4")),
    "unbound_browser_callback": ("Callback does not match initiating browser", ("G2", "G4")),
    "expired_session": ("Server-side session exceeded expiration", ("G7",)),
    "revoked_session": ("Server-side session was revoked", ("G7",)),
    "wrong_resource_audience": ("Token audience does not match resource", ("G8",)),
    "missing_resource_scope": ("Resource token lacks required scope", ("G8",)),
    "unknown_protected_action": ("Protected action has no explicit allow rule", ("G8",)),
    "unreviewed_operator_intake": (
        "Opaque intake reference is not reviewed proof",
        ("G1", "G6", "G7", "G10"),
    ),
    "missing_deployment_gate": ("One or more independent release gates are unmet", ("G1", "G10")),
}


class OfflineRequirementError(ValueError):
    """Sanitized validation error; never embeds input or provider data."""


def _unique_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise OfflineRequirementError("Invalid offline policy requirements")
        result[name] = value
    return result


def _reject_constant(_value: str) -> None:
    raise OfflineRequirementError("Invalid offline policy requirements")


def _load_json(path: Path) -> object:
    """Read a small regular file without following a terminal symlink."""
    fd: int | None = None
    try:
        if path.is_symlink():
            raise OfflineRequirementError("Invalid offline policy requirements")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode) or details.st_size > _MAX_BYTES:
            raise OfflineRequirementError("Invalid offline policy requirements")
        payload = os.read(fd, _MAX_BYTES + 1)
        if not payload or len(payload) > _MAX_BYTES:
            raise OfflineRequirementError("Invalid offline policy requirements")
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_members,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, ValueError, TypeError, OverflowError):
        raise OfflineRequirementError("Invalid offline policy requirements") from None
    finally:
        if fd is not None:
            os.close(fd)


def validate_cases(path: Path) -> int:
    """Validate only exact DENY requirements; never evaluate a real request."""
    value = _load_json(path)
    if type(value) is not dict or set(value) != {
        "schema_version",
        "phase",
        "purpose",
        "authorization_enabled",
        "review_state",
        "cases",
    }:
        raise OfflineRequirementError("Invalid offline policy requirements")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["phase"] != "1A.2.5C4"
        or value["purpose"] != "synthetic_negative_policy_requirements"
        or value["authorization_enabled"] is not False
        or value["review_state"] != "independent_review_required"
        or type(value["cases"]) is not list
        or len(value["cases"]) != len(REQUIRED_CASES)
    ):
        raise OfflineRequirementError("Invalid offline policy requirements")
    seen: set[str] = set()
    for index, case in enumerate(value["cases"]):
        if type(case) is not dict or set(case) != {"id", "violation", "expected_decision", "gates"}:
            raise OfflineRequirementError("Invalid offline policy requirements")
        case_id = case["id"]
        if type(case_id) is not str or case_id != tuple(REQUIRED_CASES)[index] or case_id in seen:
            raise OfflineRequirementError("Invalid offline policy requirements")
        seen.add(case_id)
        violation, gates = REQUIRED_CASES[case_id]
        if (
            case["violation"] != violation
            or type(case["violation"]) is not str
            or case["expected_decision"] != "DENY"
            or type(case["gates"]) is not list
            or case["gates"] != list(gates)
        ):
            raise OfflineRequirementError("Invalid offline policy requirements")
    if seen != set(REQUIRED_CASES):
        raise OfflineRequirementError("Invalid offline policy requirements")
    return len(seen)


def validate_blocked_snapshot() -> None:
    """Check committed C2/C3 metadata, never live CERN or reviewer evidence."""
    register = _load_json(_REGISTER)
    intake = _load_json(_INTAKE)
    if type(register) is not dict or type(intake) is not dict:
        raise OfflineRequirementError("Invalid offline policy requirements")
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
        raise OfflineRequirementError("Invalid offline policy requirements")
    gates = register.get("gates")
    if type(gates) is not list or len(gates) != 10:
        raise OfflineRequirementError("Invalid offline policy requirements")
    state_by_id: dict[str, str] = {}
    for gate in gates:
        if type(gate) is not dict:
            raise OfflineRequirementError("Invalid offline policy requirements")
        gate_id, state = gate.get("id"), gate.get("state")
        if type(gate_id) is not str or type(state) is not str or gate_id in state_by_id:
            raise OfflineRequirementError("Invalid offline policy requirements")
        state_by_id[gate_id] = state
    allowed_states = {"not_attested", "not_implemented", "diagnostic_only", "partial_offline"}
    if (
        set(state_by_id) != {f"G{i}" for i in range(1, 11)}
        or not set(state_by_id.values()) <= allowed_states
        or state_by_id["G1"] != "not_attested"
        or state_by_id["G6"] != "not_attested"
        or state_by_id["G7"] != "not_implemented"
    ):
        raise OfflineRequirementError("Invalid offline policy requirements")
    if (
        set(intake) != {"schema_version", "record_type", "phase", "gates"}
        or type(intake["schema_version"]) is not int
        or intake["schema_version"] != 1
        or intake["record_type"] != "non_authoritative_operator_intake"
        or intake["phase"] != "1A.2.5C3"
    ):
        raise OfflineRequirementError("Invalid offline policy requirements")
    if type(intake.get("gates")) is not list or len(intake["gates"]) != 3:
        raise OfflineRequirementError("Invalid offline policy requirements")
    for gate_id, entry in zip(("G1", "G6", "G7"), intake["gates"], strict=True):
        if type(entry) is not dict or entry != {
            "id": gate_id,
            "status": "not_supplied",
            "reference": None,
        }:
            raise OfflineRequirementError("Invalid offline policy requirements")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cases",
        type=Path,
        default=_CASES,
        help="Local synthetic DENY-only requirement fixture; no credentials",
    )
    args = parser.parse_args(argv)
    print("MODE=OFFLINE_NEGATIVE_POLICY_REQUIREMENTS")
    print("ASCA_LOGIN=DISABLED")
    print("ASCA_SESSION=DISABLED")
    print("ROLE_AUTHORIZATION=DISABLED")
    print("CHATLAS_ACCESS=DISABLED")
    print("EVIDENCE_SCOPE=REPOSITORY_SNAPSHOT_ONLY")
    try:
        count = validate_cases(args.cases)
        validate_blocked_snapshot()
    except OfflineRequirementError:
        print("RESULT=INVALID_NEGATIVE_POLICY_REQUIREMENTS")
        return 2
    for gate in ("G1", "G6", "G7"):
        print(f"{gate}=BLOCKED")
    print(f"NEGATIVE_CASES={count}")
    print("RESULT=INDEPENDENT_REVIEW_REQUIRED_NO_GRANT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
