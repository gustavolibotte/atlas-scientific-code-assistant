"""Shared fixtures, the network kill switch and live-test gating.

CI runs offline from recorded fixtures. Unless ``ASCA_LIVE=1`` every non-loopback
connection fails, and ``live`` tests are skipped. ``CI`` together with ``ASCA_LIVE`` is
refused.
"""

import os

import network_guard
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from asca.api.main import create_app


def pytest_configure(config: pytest.Config) -> None:
    network_guard.check_live_environment(os.environ)
    if not network_guard.live_enabled(os.environ):
        network_guard.install()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if network_guard.live_enabled(os.environ):
        return
    skip = pytest.mark.skip(reason="live provider test: set ASCA_LIVE=1 (never in CI)")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def app() -> FastAPI:
    return create_app()


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    with TestClient(app) as value:
        yield value
