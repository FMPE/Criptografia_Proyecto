"""Cambio de contraseña maestra: sólo se re-envuelve VK; la bóveda no se re-cifra."""

from __future__ import annotations

import base64

import pytest
from sqlalchemy import select

from client.crypto.keys import unwrap_vault_key
from client.crypto.kdf import derive_keys
from client.vault.manager import (
    OfflineError,
    SessionExpiredError,
    WeakMasterPasswordError,
    WrongCredentialsError,
)
from client.vault.models import Entry
from client.vault.storage import LocalStore
from server.app.models import SessionToken, User, VaultBlob

EMAIL = "ana@utec.edu.pe"
OLD = "Tr3s-Tristes-Tigres!"
NEW = "Otra-Clave-Muy-Larga-42"


def server_rows(app):
    with app.state.SessionLocal() as db:
        user = db.scalar(select(User))
        blob = db.scalar(select(VaultBlob))
        sessions = db.scalars(select(SessionToken)).all()
        return user, blob, sessions


@pytest.fixture
def device(manager_factory, tmp_path):
    home = tmp_path / "laptop"
    m = manager_factory(home)
    m.register(EMAIL, OLD)
    m.vault.add(Entry(service="github.com", password="hunter2"))
    m.save()  # v2
    return m, home


def test_old_password_stops_working_and_new_one_works(device, manager_factory):
    m, home = device
    m.change_password(OLD, NEW)
    m.lock()

    with pytest.raises(WrongCredentialsError):
        manager_factory(home).unlock(EMAIL, OLD)
    m2 = manager_factory(home)
    m2.unlock(EMAIL, NEW)
    assert [e.service for e in m2.vault.all()] == ["github.com"]


def test_vault_is_not_reencrypted_and_vk_is_the_same(app, device):
    m, _ = device
    _, blob_before, _ = server_rows(app)
    vk_before = m._vk
    wrapped_before = m._wrapped_vk

    m.change_password(OLD, NEW)

    user, blob_after, _ = server_rows(app)
    # El blob no cambió ni un byte: ni versión, ni nonce, ni ciphertext.
    assert (blob_after.version, blob_after.nonce, blob_after.ciphertext) == (
        blob_before.version, blob_before.nonce, blob_before.ciphertext,
    )
    assert m.version == 2
    # La VK es la misma: la envuelta nueva (distinta) desenvuelve a la misma VK.
    assert m._wrapped_vk != wrapped_before
    assert m._vk == vk_before
    secret_key = LocalStore(EMAIL, m.home).load_secret_key()
    new_keys = derive_keys(NEW, secret_key, user.salt_kdf, m.kdf_params)
    assert unwrap_vault_key(new_keys.kek, m._wrapped_vk, EMAIL) == vk_before
    # Se generó un salt_kdf nuevo.
    assert LocalStore(EMAIL, m.home).load_account().salt_kdf == user.salt_kdf


def test_wrong_old_password_changes_nothing(app, device):
    m, _ = device
    user_before, _, _ = server_rows(app)
    with pytest.raises(WrongCredentialsError):
        m.change_password("No-Es-La-Clave-123", NEW)
    user_after, _, _ = server_rows(app)
    assert user_after.auth_hash == user_before.auth_hash
    assert user_after.wrapped_vk == user_before.wrapped_vk
    assert user_after.salt_kdf == user_before.salt_kdf


def test_weak_or_same_new_password_rejected(device):
    m, _ = device
    with pytest.raises(WeakMasterPasswordError):
        m.change_password(OLD, "corta")
    with pytest.raises(WeakMasterPasswordError):
        m.change_password(OLD, OLD)


def test_offline_device_cannot_change_password(device, manager_factory):
    m, home = device
    m.online = False
    with pytest.raises(OfflineError):
        m.change_password(OLD, NEW)


def test_other_sessions_are_revoked(app, device, manager_factory, tmp_path):
    m, _ = device
    other = manager_factory(tmp_path / "pc")
    other.unlock(EMAIL, OLD, _sk_text(m))
    assert other.online

    m.change_password(OLD, NEW)

    _, _, sessions = server_rows(app)
    assert len(sessions) == 1  # sólo el token nuevo del dispositivo que cambió
    # El otro dispositivo pierde la sesión: sin passkey no puede guardar.
    other.vault.add(Entry(service="x.com"))
    with pytest.raises(SessionExpiredError):
        other.save()
    # El dispositivo que cambió sigue operando con su token nuevo.
    m.vault.add(Entry(service="gmail.com"))
    assert m.save() == 3


def test_other_device_adopts_new_password_on_next_unlock(device, manager_factory, tmp_path):
    m, _ = device
    sk = _sk_text(m)
    pc_home = tmp_path / "pc"
    other = manager_factory(pc_home)
    other.unlock(EMAIL, OLD, sk)
    other.lock()

    m.change_password(OLD, NEW)

    # En línea: la contraseña vieja ya no sirve en el otro dispositivo...
    with pytest.raises(WrongCredentialsError):
        manager_factory(pc_home).unlock(EMAIL, OLD)
    # ...y la nueva sí; además actualiza su caché local con la VK re-envuelta.
    again = manager_factory(pc_home)
    again.unlock(EMAIL, NEW)
    assert LocalStore(EMAIL, pc_home).load_cache().wrapped_vk == m._wrapped_vk


def test_offline_unlock_uses_new_password_on_changing_device(device, manager_factory):
    m, home = device
    m.change_password(OLD, NEW)
    m.lock()

    offline = manager_factory(home)
    offline.api.get_kdf_params = _raise_network  # simula sin conexión
    with pytest.raises(WrongCredentialsError):
        offline.unlock(EMAIL, OLD)
    offline.unlock(EMAIL, NEW)
    assert not offline.online and len(offline.vault) == 1


def test_endpoint_requires_session_and_old_auth_key(http):
    def b64(b):
        return base64.b64encode(b).decode()

    body = {
        "old_auth_key": b64(b"A" * 32),
        "new_auth_key": b64(b"B" * 32),
        "salt_kdf": b64(b"s" * 16),
        "kdf_params": {"memory_kib": 1024, "time_cost": 1, "parallelism": 1},
        "wrapped_vk": {"nonce": b64(b"n" * 24), "ciphertext": b64(b"w" * 48)},
    }
    assert http.post("/account/password", json=body).status_code == 401

    from tests.test_server import auth_header, register_body

    token = http.post("/register", json=register_body()).json()["token"]
    bad = {**body, "old_auth_key": b64(b"Z" * 32)}
    assert http.post("/account/password", json=bad, headers=auth_header(token)).status_code == 403
    r = http.post("/account/password", json=body, headers=auth_header(token))
    assert r.status_code == 200
    # El token viejo quedó revocado; el nuevo funciona.
    assert http.get("/vault", headers=auth_header(token)).status_code == 401
    assert http.get("/vault", headers=auth_header(r.json()["token"])).status_code == 200


# --------------------------------------------------------------------------- #
def _sk_text(m) -> str:
    from client.crypto.keys import format_secret_key

    return format_secret_key(LocalStore(EMAIL, m.home).load_secret_key())


def _raise_network(*_a, **_k):
    from client.net.api_client import NetworkError

    raise NetworkError("sin red")

