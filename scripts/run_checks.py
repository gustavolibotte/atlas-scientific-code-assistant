#!/usr/bin/env python3
"""Run every Phase 0 quality gate and produce a shareable diagnostic archive.

The collector does not read .env files, credentials, or private project materials.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DIAGNOSTICS = ROOT / "diagnostics"
LOG_DIR = DIAGNOSTICS / "latest"
ARCHIVE = DIAGNOSTICS / "phase0-diagnostics.zip"


def _run(name: str, command: list[str], *, cwd: Path = ROOT) -> dict[str, Any]:
    """Run a command and store its unmodified stdout/stderr without accessing secrets."""
    print(f"[RUN] {name}: {' '.join(command)}", flush=True)
    started = time.monotonic()
    try:
        process = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
            check=False,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1"},
        )
        status = "PASS" if process.returncode == 0 else "FAIL"
        output = process.stdout
        code = process.returncode
    except FileNotFoundError as error:
        status, code, output = "FAIL", 127, str(error)
    except subprocess.TimeoutExpired as error:
        status, code = "FAIL", 124
        output = str(error.stdout or b"") + "\nTimed out after 180 seconds."
    (LOG_DIR / f"{name}.log").write_text(output, encoding="utf-8")
    print(f"[{status}] {name} ({time.monotonic() - started:.1f}s)", flush=True)
    return {"name": name, "status": status, "exit_code": code, "command": command}


def _skip(name: str, reason: str) -> dict[str, Any]:
    print(f"[SKIPPED] {name}: {reason}", flush=True)
    (LOG_DIR / f"{name}.log").write_text(reason + "\n", encoding="utf-8")
    return {"name": name, "status": "SKIPPED", "reason": reason}


def main() -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    for old in LOG_DIR.glob("*.log"):
        old.unlink()

    results: list[dict[str, Any]] = []
    executable = sys.executable
    results.append(
        _run(
            "python_compile",
            [executable, "-m", "compileall", "-q", "src", "tests", "scripts"],
        )
    )
    results.append(
        _run(
            "backend_tests",
            [
                executable,
                "-m",
                "pytest",
                "-q",
                "--cov=asca",
                "--cov-branch",
                "--cov-report=term-missing",
                "--cov-fail-under=85",
                "--cov-report=xml:diagnostics/latest/coverage.xml",
            ],
        )
    )
    for name, cmd in (
        ("python_lint", ["ruff", "check", "src", "tests", "scripts"]),
        ("python_format", ["ruff", "format", "--check", "src", "tests", "scripts"]),
        ("python_types", ["mypy", "src"]),
    ):
        if shutil.which(cmd[0]):
            results.append(_run(name, cmd))
        else:
            results.append(
                _skip(name, f"Tool unavailable: {cmd[0]}. Install development dependencies.")
            )

    web = ROOT / "apps" / "web"
    if not (web / "node_modules").exists() or not shutil.which("npm"):
        for name in ("frontend_types", "frontend_tests", "frontend_build"):
            results.append(
                _skip(name, "Node modules/npm missing; run npm ci inside apps/web first.")
            )
    else:
        for name, command in (
            ("frontend_types", ["npm", "run", "typecheck"]),
            ("frontend_tests", ["npm", "run", "test:run"]),
            ("frontend_build", ["npm", "run", "build"]),
        ):
            results.append(_run(name, command, cwd=web))

    environment = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "node": _version(["node", "--version"]),
        "npm": _version(["npm", "--version"]),
        "uv": _version(["uv", "--version"]),
    }
    summary = {
        "project": "atlas-scientific-code-assistant",
        "phase": "0",
        "environment": environment,
        "checks": results,
        "pass": sum(item["status"] == "PASS" for item in results),
        "fail": sum(item["status"] == "FAIL" for item in results),
        "skipped": sum(item["status"] == "SKIPPED" for item in results),
    }
    summary["accepted"] = summary["fail"] == 0 and summary["skipped"] == 0
    (LOG_DIR / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")

    with zipfile.ZipFile(ARCHIVE, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(LOG_DIR.iterdir()):
            if path.is_file():
                archive.write(path, path.relative_to(ROOT))

    print(f"\nDiagnostic ZIP: {ARCHIVE}")
    print(f"PASS={summary['pass']} FAIL={summary['fail']} SKIPPED={summary['skipped']}")
    gate = "ELIGIBLE FOR REVIEW" if summary["accepted"] else "NOT READY — REVIEW FAILURES/SKIPS"
    print(f"Gate: {gate}")
    return 0 if summary["accepted"] else 1


def _version(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
        return result.stdout.strip() if result.returncode == 0 else "unavailable"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unavailable"


if __name__ == "__main__":
    raise SystemExit(main())
