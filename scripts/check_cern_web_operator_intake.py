#!/usr/bin/env python3
"""Offline, non-authoritative intake checker for future CERN web-client evidence.

A structurally valid record is NOT provider attestation, authorization, login
readiness, or proof that evidence references exist. Never print record content.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path
from typing import Final

_ROOT: Final = Path(__file__).resolve().parents[1]
_DEFAULT_RECORD: Final = _ROOT / "docs/security/cern-web-operator-intake-template.json"
_MAX_BYTES: Final = 4096
_GATE_IDS: Final = ("G1", "G6", "G7")
_GATE_STATUSES: Final = frozenset({"not_supplied", "submitted_for_review"})
_REFERENCE: Final = re.compile(r"EVIDENCE-[0-9]{4,8}\Z", re.ASCII)


class EvidenceIntakeError(ValueError):
    """Sanitized failure; no record data, file path or provider detail."""


def _unique_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise EvidenceIntakeError("Invalid intake document")
        result[name] = value
    return result


def _reject_constant(_literal: str) -> None:
    raise EvidenceIntakeError("Invalid intake document")


def _bounded_regular_file(path: Path) -> bytes:
    """Read only a small regular file, without following its last symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor: int | None = None
    try:
        if path.is_symlink():
            raise EvidenceIntakeError("Invalid intake document")
        descriptor = os.open(path, flags)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size > _MAX_BYTES:
            raise EvidenceIntakeError("Invalid intake document")
        data = os.read(descriptor, _MAX_BYTES + 1)
        if not data or len(data) > _MAX_BYTES:
            raise EvidenceIntakeError("Invalid intake document")
        return data
    except (OSError, TypeError, ValueError):
        raise EvidenceIntakeError("Invalid intake document") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_intake(path: Path) -> tuple[tuple[str, str], ...]:
    """Validate an untrusted declaration. Never produce a readiness decision."""
    try:
        data = _bounded_regular_file(path)
        obj = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_members,
            parse_constant=_reject_constant,
        )
        if type(obj) is not dict or set(obj) != {
            "schema_version",
            "record_type",
            "phase",
            "gates",
        }:
            raise EvidenceIntakeError("Invalid intake document")
        if (
            type(obj["schema_version"]) is not int
            or obj["schema_version"] != 1
            or obj["record_type"] != "non_authoritative_operator_intake"
            or obj["phase"] != "1A.2.5C3"
            or type(obj["gates"]) is not list
            or len(obj["gates"]) != len(_GATE_IDS)
        ):
            raise EvidenceIntakeError("Invalid intake document")
        statuses: list[tuple[str, str]] = []
        for index, gate in enumerate(obj["gates"]):
            if type(gate) is not dict or set(gate) != {"id", "status", "reference"}:
                raise EvidenceIntakeError("Invalid intake document")
            gate_id = _GATE_IDS[index]
            status = gate["status"]
            reference = gate["reference"]
            if (
                type(gate["id"]) is not str
                or gate["id"] != gate_id
                or type(status) is not str
                or status not in _GATE_STATUSES
            ):
                raise EvidenceIntakeError("Invalid intake document")
            if status == "not_supplied":
                if reference is not None:
                    raise EvidenceIntakeError("Invalid intake document")
            elif type(reference) is not str or _REFERENCE.fullmatch(reference) is None:
                raise EvidenceIntakeError("Invalid intake document")
            statuses.append((gate_id, status))
        return tuple(statuses)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, OverflowError):
        raise EvidenceIntakeError("Invalid intake document") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--record",
        type=Path,
        default=_DEFAULT_RECORD,
        help="Local non-secret evidence intake JSON; never use tokens or credentials",
    )
    args = parser.parse_args(argv)
    print("MODE=OFFLINE_OPERATOR_EVIDENCE_INTAKE")
    print("ASCA_LOGIN=DISABLED")
    print("ASCA_SESSION=DISABLED")
    print("ROLE_AUTHORIZATION=DISABLED")
    print("CHATLAS_ACCESS=DISABLED")
    try:
        statuses = read_intake(args.record)
    except EvidenceIntakeError:
        print("RESULT=INVALID_EVIDENCE_RECORD")
        return 2
    print("RECORD=STRUCTURALLY_VALID_NON_AUTHORITATIVE")
    for gate_id, status in statuses:
        label = "NOT_SUPPLIED" if status == "not_supplied" else "SUBMITTED_UNVERIFIED"
        print(f"{gate_id}={label}")
    print("RESULT=OPERATOR_REVIEW_REQUIRED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
