"""Fixtures comunes. Las pruebas usan Argon2id barato para correr rápido;
los parámetros reales (64 MiB, t=3, p=4) se prueban aparte en test_kdf."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from client.crypto import kdf
from client.crypto.kdf import KdfParams
from client.net.api_client import ApiClient
from client.vault.manager import VaultManager
from server.app.config import Settings
from server.app.main import create_app

FAST_PARAMS = KdfParams(memory_kib=1024, time_cost=1, parallelism=1)


@pytest.fixture(autouse=True)
def fast_kdf_minimum(monkeypatch):
    monkeypatch.setattr(kdf, "MIN_PARAMS", FAST_PARAMS)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite:///:memory:",
        argon2_memory_kib=1024,
        argon2_time_cost=1,
        argon2_parallelism=1,
        min_client_memory_kib=FAST_PARAMS.memory_kib,
        min_client_time_cost=FAST_PARAMS.time_cost,
        login_max_failures=3,
        fake_salt_key=b"k" * 32,
    )


@pytest.fixture
def app(settings):
    return create_app(settings)


@pytest.fixture
def http(app) -> TestClient:
    return TestClient(app, base_url="https://testserver")


def make_manager(app, home) -> VaultManager:
    api = ApiClient("https://testserver", http_client=TestClient(app, base_url="https://testserver"))
    return VaultManager(api, home=home, kdf_params=FAST_PARAMS)


@pytest.fixture
def manager_factory(app, tmp_path):
    counter = {"n": 0}

    def factory(home=None):
        counter["n"] += 1
        return make_manager(app, home or tmp_path / f"device{counter['n']}")

    return factory
