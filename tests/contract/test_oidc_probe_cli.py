"""The public metadata probe must remain offline unless explicitly requested."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_cern_oidc_discovery.py"


def test_default_probe_disables_network_and_reports_no_login() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0
    assert "OFFLINE_ONLY" in result.stdout
    assert "no network request" in result.stdout
    assert "https://auth.cern.ch/auth/realms/cern" in result.stdout
    assert "VALIDATED_PUBLIC_METADATA" not in result.stdout


def test_probe_help_explains_live_is_opt_in() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0
    assert "--live" in result.stdout
    assert "public metadata" in result.stdout
