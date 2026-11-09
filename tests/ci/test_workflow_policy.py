"""Dependency-free policy regression tests for GitHub Actions workflows."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def workflow(name: str) -> str:
    """Load a version-controlled CI workflow as text."""
    return (WORKFLOWS / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("name", ["backend.yml", "frontend.yml"])
def test_workflow_events_are_scoped_to_main(name: str) -> None:
    content = workflow(name)
    assert re.search(r"(?m)^on:\s*$", content)
    assert re.search(r"(?m)^  push:\s*\n    branches: \[main\]", content)
    assert re.search(r"(?m)^  pull_request:\s*\n    branches: \[main\]", content)
    assert "pull_request_target:" not in content
    assert "workflow_run:" not in content


@pytest.mark.parametrize("name", ["backend.yml", "frontend.yml"])
def test_token_permissions_and_checkout_are_read_only(name: str) -> None:
    content = workflow(name)
    assert re.search(r"(?m)^permissions:\s*\n  contents: read\s*$", content)
    assert "actions/checkout@v7" in content
    assert "persist-credentials: false" in content
    assert "contents: write" not in content


@pytest.mark.parametrize("name", ["backend.yml", "frontend.yml"])
def test_runners_are_explicit_and_updated(name: str) -> None:
    content = workflow(name)
    assert "ubuntu-24.04" in content
    assert "ubuntu-26.04" in content
    assert "ubuntu-latest" not in content
    assert "timeout-minutes:" in content
    assert "cancel-in-progress: true" in content


def test_backend_runs_three_python_versions_and_macos() -> None:
    content = workflow("backend.yml")
    assert "os: [ubuntu-24.04, ubuntu-26.04, macos-latest]" in content
    assert "python-version: ['3.11', '3.12', '3.13']" in content
    assert "astral-sh/setup-uv@v10" in content
    assert "version: '0.13.7'" in content
    assert "uv sync --all-groups --locked" in content
    assert "Verify selected Python version" in content
    assert "--cov-fail-under=85" in content


def test_frontend_runs_on_both_ubuntu_versions() -> None:
    content = workflow("frontend.yml")
    assert "os: [ubuntu-24.04, ubuntu-26.04]" in content
    assert "actions/setup-node@v7" in content
    assert "node-version: '22'" in content
    assert "npm ci" in content
    assert "npm run typecheck" in content
    assert "npm run test:run" in content
    assert "npm run build" in content


@pytest.mark.parametrize(
    ("name", "job", "gate"),
    [
        ("backend.yml", "backend", "Backend quality gate"),
        ("frontend.yml", "frontend", "Frontend quality gate"),
    ],
)
def test_stable_gate_requires_matrix_success(name: str, job: str, gate: str) -> None:
    content = workflow(name)
    assert f"name: {gate}" in content
    assert "if: ${{ always() }}" in content
    assert f"needs: [{job}]" in content
    assert f"MATRIX_RESULT: ${{{{ needs.{job}.result }}}}" in content
    assert "test \"$MATRIX_RESULT\" = 'success'" in content


def test_legacy_node20_actions_are_not_used() -> None:
    content = "\n".join(workflow(name) for name in ("backend.yml", "frontend.yml"))
    assert "actions/checkout@v4" not in content
    assert "actions/setup-node@v4" not in content
    assert "astral-sh/setup-uv@v6" not in content
