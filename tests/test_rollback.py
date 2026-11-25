"""Anti-rollback: el cliente rechaza blobs más viejos que la versión que ya verificó.

El "servidor malicioso" se simula reescribiendo directamente la fila de la bóveda
en su base de datos, con una copia íntegra (tag válido) de una versión anterior.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from client.vault.manager import IntegrityError, RollbackError
from client.vault.models import Entry
from client.vault.storage import LocalStore
from server.app.models import VaultBlob

EMAIL = "franco@utec.edu.pe"
PW = "Tr3s-Tristes-Tigres!"


def snapshot(app) -> dict:
    """Copia la fila de la bóveda tal como la tiene el servidor (blob íntegro)."""
    with app.state.SessionLocal() as db:
        row = db.scalar(select(VaultBlob))
        return {"version": row.version, "nonce": row.nonce, "ciphertext": row.ciphertext}


def serve_old_blob(app, old: dict, version: int | None = None) -> None:
    """El servidor vuelve a entregar un blob viejo (opcionalmente con otro número)."""
    with app.state.SessionLocal() as db:
        row = db.scalar(select(VaultBlob))
        row.version = old["version"] if version is None else version
        row.nonce, row.ciphertext = old["nonce"], old["ciphertext"]
        db.commit()


def add_and_save(m, service: str) -> int:
    m.vault.add(Entry(service=service))
    return m.save()


@pytest.fixture
def device(manager_factory, tmp_path):
    """Dispositivo con la cuenta registrada; devuelve (manager, home)."""
    home = tmp_path / "laptop"
    m = manager_factory(home)
    m.secret_key_text = m.register(EMAIL, PW)
    return m, home


# --------------------------------------------------------------------------- #
def test_unlock_rejects_old_blob(app, device, manager_factory):
    m, home = device
    add_and_save(m, "github.com")  # v2
    v2 = snapshot(app)
    add_and_save(m, "gmail.com")  # v3
    add_and_save(m, "banco.pe")  # v4
    m.lock()

    serve_old_blob(app, v2)
    m2 = manager_factory(home)
    with pytest.raises(RollbackError, match="v2.*v4"):
        m2.unlock(EMAIL, PW)
    assert not m2.is_unlocked
    # Nada local se sobrescribió con el blob viejo
    store = LocalStore(EMAIL, home)
    assert store.load_cache().sealed.version == 4
    assert store.load_max_version() == 4


def test_pull_rejects_old_blob_and_keeps_memory(app, device):
    m, _ = device
    add_and_save(m, "github.com")  # v2
    v2 = snapshot(app)
    add_and_save(m, "gmail.com")  # v3

    serve_old_blob(app, v2)
    with pytest.raises(RollbackError):
        m.pull()
    assert m.version == 3
    assert [e.service for e in m.vault.all()] == ["github.com", "gmail.com"]
    assert m.store.load_cache().sealed.version == 3


def test_passkey_unlock_rejects_old_blob(app, device, manager_factory):
    m, home = device
    m.create_passkey("laptop")  # v2 (la privada ya está en la bóveda)
    v2 = snapshot(app)
    add_and_save(m, "github.com")  # v3
    m.lock()

    serve_old_blob(app, v2)
    m2 = manager_factory(home)
    with pytest.raises(RollbackError):
        m2.unlock(EMAIL, PW, use_passkey=True)
    assert not m2.is_unlocked


def test_legitimate_newer_version_is_accepted(device, manager_factory, tmp_path):
    a, _ = device
    b = manager_factory(tmp_path / "desktop")
    b.unlock(EMAIL, PW, a.secret_key_text)

    add_and_save(a, "github.com")  # v2
    add_and_save(a, "gmail.com")  # v3
    b.pull()
    assert b.version == 3
    assert b.store.load_max_version() == 3


def test_relabeled_version_fails_integrity(app, device, manager_factory):
    """El número de versión es confiable porque va en el AAD: relabelar rompe el tag."""
    m, home = device
    add_and_save(m, "github.com")  # v2
    v2 = snapshot(app)
    add_and_save(m, "gmail.com")  # v3
    m.lock()

    serve_old_blob(app, v2, version=9)  # blob de v2 presentado como v9
    with pytest.raises(IntegrityError):
        manager_factory(home).unlock(EMAIL, PW)


def test_new_device_trusts_first_version_it_sees(app, device, manager_factory, tmp_path):
    """Límite conocido (confianza en el primer uso): sin marca de agua no hay con qué comparar."""
    m, _ = device
    add_and_save(m, "github.com")  # v2
    v2 = snapshot(app)
    add_and_save(m, "gmail.com")  # v3

    serve_old_blob(app, v2)
    fresh = manager_factory(tmp_path / "nuevo")
    fresh.unlock(EMAIL, PW, m.secret_key_text)
    assert fresh.version == 2


def test_watermark_persists_and_never_decreases(tmp_path):
    store = LocalStore(EMAIL, tmp_path)
    assert store.load_max_version() == 0
    assert store.record_version(5) == 5
    assert store.record_version(3) == 5
    assert LocalStore(EMAIL, tmp_path).load_max_version() == 5
