"""Flujo completo cliente ↔ servidor: lo que se mostraría en la demo."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from client.crypto import keys
from client.vault.manager import (
    IntegrityError,
    SecretKeyRequiredError,
    SyncConflictError,
    WeakMasterPasswordError,
    WrongCredentialsError,
)
from client.vault.models import Entry
from server.app.models import User, VaultBlob

EMAIL = "franco@utec.edu.pe"
PW = "Tr3s-Tristes-Tigres!"


def test_register_add_save_and_unlock_on_same_device(manager_factory, tmp_path):
    home = tmp_path / "laptop"
    m = manager_factory(home)
    sk_text = m.register(EMAIL, PW)
    assert sk_text.startswith("PM1-")

    m.vault.add(Entry(service="github.com", username="franco", password="hunter2!"))
    assert m.save() == 2
    m.lock()
    assert not m.is_unlocked

    m2 = manager_factory(home)
    m2.unlock(EMAIL, PW)
    assert m2.version == 2
    assert m2.vault.search("github")[0].password == "hunter2!"


def test_new_device_needs_secret_key(manager_factory):
    m = manager_factory()
    sk_text = m.register(EMAIL, PW)
    m.vault.add(Entry(service="gmail.com", password="p"))
    m.save()

    other = manager_factory()
    with pytest.raises(SecretKeyRequiredError):
        other.unlock(EMAIL, PW)
    # Contraseña correcta + Secret Key equivocada → no entra
    with pytest.raises(WrongCredentialsError):
        other.unlock(EMAIL, PW, keys.format_secret_key(keys.generate_secret_key()))
    other.unlock(EMAIL, PW, sk_text)
    assert other.vault.search("gmail")[0].password == "p"
    # Ahora la Secret Key quedó guardada en el dispositivo
    other.lock()
    other.unlock(EMAIL, PW)


def test_wrong_password(manager_factory, tmp_path):
    m = manager_factory(tmp_path / "d")
    m.register(EMAIL, PW)
    m.lock()
    with pytest.raises(WrongCredentialsError):
        manager_factory(tmp_path / "d").unlock(EMAIL, PW + "x")


def test_weak_master_password_rejected(manager_factory):
    with pytest.raises(WeakMasterPasswordError):
        manager_factory().register(EMAIL, "corta")
    with pytest.raises(WeakMasterPasswordError):
        manager_factory().register(EMAIL, "aaaaaaaaaaaaaaaa")


def test_concurrent_edit_conflict(manager_factory, tmp_path):
    a = manager_factory(tmp_path / "a")
    sk_text = a.register(EMAIL, PW)
    b = manager_factory(tmp_path / "b")
    b.unlock(EMAIL, PW, sk_text)

    a.vault.add(Entry(service="desde-a"))
    a.save()
    b.vault.add(Entry(service="desde-b"))
    with pytest.raises(SyncConflictError):
        b.save()
    b.pull()
    assert [e.service for e in b.vault.all()] == ["desde-a"]


def test_server_sees_only_ciphertext(app, manager_factory):
    m = manager_factory()
    m.register(EMAIL, PW)
    m.vault.add(Entry(service="banco.pe", username="franco", password="SuperSecreta123"))
    m.save()
    with app.state.SessionLocal() as db:
        blob = db.scalar(select(VaultBlob))
        user = db.scalar(select(User))
    for needle in (b"banco", b"franco", b"SuperSecreta123", PW.encode()):
        assert needle not in blob.ciphertext
        assert needle not in user.wrapped_vk


def test_tampered_blob_on_server_is_detected(app, manager_factory, tmp_path):
    m = manager_factory(tmp_path / "d")
    m.register(EMAIL, PW)
    m.vault.add(Entry(service="x"))
    m.save()
    m.lock()
    with app.state.SessionLocal() as db:
        blob = db.scalar(select(VaultBlob))
        ct = bytearray(blob.ciphertext)
        ct[10] ^= 0xFF
        blob.ciphertext = bytes(ct)
        db.commit()
    with pytest.raises(IntegrityError):
        manager_factory(tmp_path / "d").unlock(EMAIL, PW)


def test_local_cache_is_encrypted(manager_factory, tmp_path):
    m = manager_factory(tmp_path / "d")
    m.register(EMAIL, PW)
    m.vault.add(Entry(service="netflix.com", password="Pelis2024!"))
    m.save()
    for f in m.store.dir.iterdir():
        data = f.read_bytes()
        assert b"netflix" not in data and b"Pelis2024" not in data
