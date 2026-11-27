"""Passkeys Ed25519: primitiva, protocolo del servidor y flujos completos."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select, update

from client.crypto import passkeys as pkc
from client.net.api_client import AuthError
from client.vault.manager import (
    PasskeyAuthError,
    PasskeyUnavailableError,
    SessionExpiredError,
    WrongCredentialsError,
)
from client.vault.models import Entry, Vault
from server.app import passkeys as server_pk
from server.app.models import AuthChallenge, Passkey, SessionToken, VaultBlob

EMAIL = "franco@utec.edu.pe"
PW = "Tr3s-Tristes-Tigres!"


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


# =========================================================================== #
# Primitiva
# =========================================================================== #
def test_sign_and_verify():
    seed, pub = pkc.generate_keypair()
    assert len(seed) == 32 and len(pub) == 32
    assert pkc.public_key_from_seed(seed) == pub
    msg = pkc.auth_message(EMAIL, "abc", bytes(32))
    sig = pkc.sign(seed, msg)
    assert len(sig) == 64
    assert pkc.verify(pub, msg, sig)


def test_ed25519_is_deterministic():
    seed, _ = pkc.generate_keypair()
    msg = pkc.auth_message(EMAIL, "abc", bytes(32))
    assert pkc.sign(seed, msg) == pkc.sign(seed, msg)


def test_signature_is_bound_to_email_challenge_and_domain():
    seed, pub = pkc.generate_keypair()
    sig = pkc.sign(seed, pkc.auth_message(EMAIL, "abc", bytes(32)))
    assert not pkc.verify(pub, pkc.auth_message("otro@utec.edu.pe", "abc", bytes(32)), sig)
    assert not pkc.verify(pub, pkc.auth_message(EMAIL, "abd", bytes(32)), sig)
    assert not pkc.verify(pub, pkc.auth_message(EMAIL, "abc", b"\x01" * 32), sig)
    # Una prueba de registro no sirve como firma de login
    reg_sig = pkc.sign(seed, pkc.registration_message(EMAIL, pub))
    assert not pkc.verify(pub, pkc.auth_message(EMAIL, "abc", bytes(32)), reg_sig)


def test_client_and_server_build_identical_messages():
    _, pub = pkc.generate_keypair()
    ch = bytes(range(32))
    assert pkc.auth_message(EMAIL, "id1", ch) == server_pk.auth_message(EMAIL, "id1", ch)
    assert pkc.registration_message(EMAIL, pub) == server_pk.registration_message(EMAIL, pub)


def test_vault_serializes_passkeys_and_reads_old_format():
    from client.vault.models import Passkey as VaultPasskey

    v = Vault([Entry(service="x")])
    v.add_passkey(VaultPasskey(1, "laptop", "c2VlZA==", "cHVi"))
    v2 = Vault.from_bytes(v.to_bytes())
    assert v2.latest_passkey().label == "laptop"
    assert [e.service for e in v2.search("")] == ["x"]  # no aparece como entrada
    old = b'{"format":1,"entries":[]}'
    assert Vault.from_bytes(old).passkeys() == []


# =========================================================================== #
# Servidor (HTTP directo)
# =========================================================================== #
@pytest.fixture
def account(manager_factory):
    """Cuenta registrada; devuelve (manager, token)."""
    m = manager_factory()
    m.register(EMAIL, PW)
    return m


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def register_pub(http, token, seed, pub, email=EMAIL, label="laptop"):
    proof = pkc.sign(seed, pkc.registration_message(email, pub))
    return http.post(
        "/passkeys",
        json={"public_key": b64(pub), "label": label, "proof": b64(proof)},
        headers=auth(token),
    )


def challenge(http, email=EMAIL):
    data = http.post("/auth/challenge", json={"email": email}).json()
    return data["challenge_id"], base64.b64decode(data["challenge"])


def verify(http, cid, credential_id, sig, email=EMAIL):
    return http.post(
        "/auth/verify",
        json={
            "email": email,
            "challenge_id": cid,
            "credential_id": credential_id,
            "signature": b64(sig),
        },
    )


@pytest.fixture
def registered(http, account):
    seed, pub = pkc.generate_keypair()
    r = register_pub(http, account.api.token, seed, pub)
    assert r.status_code == 201
    return seed, r.json()["credential_id"]


def test_register_requires_session(http):
    seed, pub = pkc.generate_keypair()
    assert register_pub(http, "inventado", seed, pub).status_code == 401


def test_register_requires_proof_of_possession(http, account):
    seed, pub = pkc.generate_keypair()
    _, other_pub = pkc.generate_keypair()
    # Prueba firmada con otra llave: no demuestra posesión de `other_pub`
    proof = pkc.sign(seed, pkc.registration_message(EMAIL, other_pub))
    r = http.post(
        "/passkeys",
        json={"public_key": b64(other_pub), "label": "x", "proof": b64(proof)},
        headers=auth(account.api.token),
    )
    assert r.status_code == 422


def test_login_with_passkey(http, registered):
    seed, credential_id = registered
    cid, ch = challenge(http)
    r = verify(http, cid, credential_id, pkc.sign(seed, pkc.auth_message(EMAIL, cid, ch)))
    assert r.status_code == 200
    assert http.get("/vault", headers=auth(r.json()["token"])).status_code == 200
    listed = http.get("/passkeys", headers=auth(r.json()["token"])).json()
    assert listed[0]["last_used_at"] is not None


def test_challenge_cannot_be_replayed(http, registered):
    seed, credential_id = registered
    cid, ch = challenge(http)
    sig = pkc.sign(seed, pkc.auth_message(EMAIL, cid, ch))
    assert verify(http, cid, credential_id, sig).status_code == 200
    assert verify(http, cid, credential_id, sig).status_code == 401


def test_failed_attempt_also_consumes_challenge(http, registered):
    seed, credential_id = registered
    cid, ch = challenge(http)
    assert verify(http, cid, credential_id, b"\x00" * 64).status_code == 401
    good = pkc.sign(seed, pkc.auth_message(EMAIL, cid, ch))
    assert verify(http, cid, credential_id, good).status_code == 401


def test_expired_challenge(app, http, registered):
    seed, credential_id = registered
    cid, ch = challenge(http)
    with app.state.SessionLocal() as db:
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.execute(update(AuthChallenge).values(expires_at=past))
        db.commit()
    sig = pkc.sign(seed, pkc.auth_message(EMAIL, cid, ch))
    assert verify(http, cid, credential_id, sig).status_code == 401


def test_wrong_key_signature_rejected(http, registered):
    _, credential_id = registered
    attacker_seed, _ = pkc.generate_keypair()
    cid, ch = challenge(http)
    sig = pkc.sign(attacker_seed, pkc.auth_message(EMAIL, cid, ch))
    assert verify(http, cid, credential_id, sig).status_code == 401


def test_cannot_use_another_users_credential(http, registered, manager_factory):
    seed, credential_id = registered
    manager_factory().register("mallory@utec.edu.pe", PW)
    cid, ch = challenge(http, "mallory@utec.edu.pe")
    sig = pkc.sign(seed, pkc.auth_message("mallory@utec.edu.pe", cid, ch))
    assert verify(http, cid, credential_id, sig, email="mallory@utec.edu.pe").status_code == 401


def test_cannot_use_another_users_challenge(http, registered, manager_factory):
    seed, credential_id = registered
    manager_factory().register("mallory@utec.edu.pe", PW)
    cid, ch = challenge(http, "mallory@utec.edu.pe")  # challenge emitido para otro usuario
    sig = pkc.sign(seed, pkc.auth_message(EMAIL, cid, ch))
    assert verify(http, cid, credential_id, sig).status_code == 401


def test_revoked_passkey_rejected(http, account, registered):
    seed, credential_id = registered
    token = account.api.token
    assert http.delete(f"/passkeys/{credential_id}", headers=auth(token)).status_code == 204
    assert http.delete(f"/passkeys/{credential_id}", headers=auth(token)).status_code == 404
    cid, ch = challenge(http)
    sig = pkc.sign(seed, pkc.auth_message(EMAIL, cid, ch))
    assert verify(http, cid, credential_id, sig).status_code == 401


def test_unknown_email_gets_same_shaped_challenge(http, registered):
    real = http.post("/auth/challenge", json={"email": EMAIL}).json()
    fake = http.post("/auth/challenge", json={"email": "nadie@utec.edu.pe"}).json()
    assert real.keys() == fake.keys()
    assert len(base64.b64decode(fake["challenge"])) == 32
    assert len(fake["challenge_id"]) == len(real["challenge_id"])


def test_verify_is_rate_limited(http, registered):
    _, credential_id = registered
    for _ in range(3):  # login_max_failures = 3 en conftest
        cid, _ch = challenge(http)
        assert verify(http, cid, credential_id, b"\x00" * 64).status_code == 401
    assert http.post("/auth/challenge", json={"email": EMAIL}).status_code == 429


# =========================================================================== #
# Flujos completos con VaultManager
# =========================================================================== #
def expire_sessions(app):
    with app.state.SessionLocal() as db:
        db.execute(delete(SessionToken))
        db.commit()


def test_private_key_never_reaches_server(app, account):
    pk = account.create_passkey("laptop")
    seed = base64.b64decode(pk.private_key)
    with app.state.SessionLocal() as db:
        stored = db.scalar(select(Passkey))
        blob = db.scalar(select(VaultBlob))
    assert stored.public_key == base64.b64decode(pk.public_key)
    assert seed not in stored.public_key
    assert seed not in blob.ciphertext
    assert pk.private_key.encode() not in blob.ciphertext
    assert account.version == 2  # la privada quedó guardada en la bóveda cifrada


def test_expired_session_is_renewed_with_passkey(app, account):
    account.create_passkey("laptop")
    account.vault.add(Entry(service="github.com"))
    expire_sessions(app)
    assert account.save() == 3  # se renovó solo: sin pedir la contraseña
    assert account.auth_method == "passkey"


def test_expired_session_without_passkey(app, account):
    expire_sessions(app)
    with pytest.raises(SessionExpiredError):
        account.save()


def test_unlock_with_passkey_never_sends_auth_key(account, manager_factory):
    account.create_passkey("laptop")
    home = account.home
    account.lock()

    m = manager_factory(home)

    def forbidden(*a, **kw):
        raise AssertionError("No debe enviarse AuthKey en el login con passkey")

    m.api.login = forbidden
    m.unlock(EMAIL, PW, use_passkey=True)
    assert m.online and m.auth_method == "passkey"
    m.vault.add(Entry(service="gmail.com"))
    m.save()


def test_unlock_with_passkey_still_needs_master_password(account, manager_factory):
    account.create_passkey("laptop")
    home = account.home
    account.lock()
    with pytest.raises(WrongCredentialsError):
        manager_factory(home).unlock(EMAIL, PW + "x", use_passkey=True)


def test_unlock_with_passkey_on_new_device_is_refused(account, manager_factory):
    account.create_passkey("laptop")
    with pytest.raises(PasskeyUnavailableError):
        manager_factory().unlock(EMAIL, PW, use_passkey=True)


def test_unlock_with_passkey_requires_a_passkey(account, manager_factory):
    home = account.home
    account.lock()
    with pytest.raises(PasskeyUnavailableError):
        manager_factory(home).unlock(EMAIL, PW, use_passkey=True)


def test_revoke_passkey(account, manager_factory):
    pk = account.create_passkey("laptop")
    other = account.create_passkey("respaldo")
    account.revoke_passkey(other.credential_id)
    assert [p.label for p in account.vault.passkeys()] == ["laptop"]
    assert len(account.api.list_passkeys()) == 1
    account.login_with_passkey()  # la que queda sigue sirviendo

    # Si el servidor ya no la tiene (revocada desde otro dispositivo), el login falla
    account.api.delete_passkey(pk.credential_id)
    with pytest.raises(PasskeyAuthError):
        account.login_with_passkey()


def test_create_passkey_rolls_back_if_vault_save_fails(account, monkeypatch):
    from client.vault.manager import SyncConflictError

    def boom():
        raise SyncConflictError("conflicto simulado")

    monkeypatch.setattr(account, "save", boom)
    with pytest.raises(SyncConflictError):
        account.create_passkey("laptop")
    assert account.vault.passkeys() == []
    assert account.api.list_passkeys() == []


def test_api_rejects_passkey_calls_without_session(account):
    account.api.logout()
    with pytest.raises(AuthError):
        account.api.list_passkeys()


# =========================================================================== #
# Passkey + cambio de contraseña hecho en OTRO dispositivo
# =========================================================================== #
NEW_PW = "0tra-Clave-Muy-Larga#9"


@pytest.fixture
def changed_elsewhere(manager_factory, tmp_path):
    """El dispositivo A tiene passkey y está bloqueado; el B cambia la contraseña maestra."""
    a = manager_factory(tmp_path / "a")
    sk_text = a.register("otra@utec.edu.pe", PW)
    a.create_passkey("laptop")
    a.lock()
    b = manager_factory(tmp_path / "b")
    b.unlock("otra@utec.edu.pe", PW, sk_text)
    b.change_password(PW, NEW_PW)
    b.lock()
    return tmp_path / "a", "otra@utec.edu.pe"


def test_old_password_plus_passkey_is_rejected_after_remote_change(changed_elsewhere, manager_factory):
    home, email = changed_elsewhere
    m = manager_factory(home)
    with pytest.raises(WrongCredentialsError, match="cambió en otro dispositivo"):
        m.unlock(email, PW, use_passkey=True)
    assert not m.is_unlocked
    # Tampoco queda una segunda oportunidad: la caché ya tiene la VK envuelta nueva.
    with pytest.raises(WrongCredentialsError):
        manager_factory(home).unlock(email, PW, use_passkey=True)


def test_new_password_with_passkey_needs_one_normal_unlock(changed_elsewhere, manager_factory):
    home, email = changed_elsewhere
    with pytest.raises(WrongCredentialsError, match="desbloquea una vez sin passkey"):
        manager_factory(home).unlock(email, NEW_PW, use_passkey=True)

    normal = manager_factory(home)
    normal.unlock(email, NEW_PW)  # actualiza salt y VK envuelta locales
    normal.lock()

    m = manager_factory(home)
    m.unlock(email, NEW_PW, use_passkey=True)
    assert m.is_unlocked and m.auth_method == "passkey"
    m.lock()
    with pytest.raises(WrongCredentialsError):
        manager_factory(home).unlock(email, PW, use_passkey=True)


def test_passkey_unlock_without_changes_derives_only_once(account, manager_factory, monkeypatch):
    account.create_passkey("laptop")
    home = account.home
    account.lock()
    import client.vault.manager as mgr_mod

    calls = []
    real = mgr_mod.derive_keys
    monkeypatch.setattr(mgr_mod, "derive_keys", lambda *a, **k: calls.append(1) or real(*a, **k))
    manager_factory(home).unlock(EMAIL, PW, use_passkey=True)
    assert len(calls) == 1  # salt y parámetros iguales: se reutiliza la KEK local
