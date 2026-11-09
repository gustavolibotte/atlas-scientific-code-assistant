"""Shared fixtures for deterministic HTTP tests."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from asca.api.main import create_app


@pytest.fixture
def app() -> FastAPI:
    return create_app()


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    with TestClient(app) as value:
        yield value
