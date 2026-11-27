"""Padding del blob y respaldo cifrado (.pmx)."""

from __future__ import annotations

import base64
import json

import pytest

from client.crypto import aead
from client.crypto.keys import generate_vault_key
from client.vault.blob import PAD_BLOCK, PaddingError, SealedVault, open_vault, pad, seal_vault, unpad, vault_aad
from client.vault.export import ExportAuthError, ExportError, export_vault, import_vault
from client.vault.models import Entry, Vault
from tests.conftest import FAST_PARAMS

UID = "ana@utec.edu.pe"
BACKUP_PW = "Respaldo-Seguro-2026!"


def vault_with(n: int) -> Vault:
    v = Vault()
    for i in range(n):
        v.add(Entry(service=f"servicio{i}.com", username=f"user{i}", password=f"pw-{i:04d}"))
    return v


# --------------------------------------------------------------------------- #
# Padding
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("data", [b"", b"{}", b"x" * (PAD_BLOCK - 5), b"x" * PAD_BLOCK, b"y" * 9000])
def test_pad_roundtrip_and_block_multiple(data):
    p = pad(data)
    assert len(p) % PAD_BLOCK == 0 and len(p) >= len(data) + 5
    assert unpad(p) == data


def test_size_does_not_reveal_number_of_entries():
    vk = generate_vault_key()
    sizes = {len(seal_vault(vk, vault_with(n), 1, UID).ciphertext) for n in range(0, 10)}
    assert sizes == {PAD_BLOCK + aead.TAG_SIZE}


def test_size_grows_only_in_whole_blocks():
    vk = generate_vault_key()
    for n in (0, 30, 80):
        ct = seal_vault(vk, vault_with(n), 1, UID).ciphertext
        assert (len(ct) - aead.TAG_SIZE) % PAD_BLOCK == 0


def test_padded_vault_roundtrip():
    vk = generate_vault_key()
    v = vault_with(5)
    assert len(open_vault(vk, seal_vault(vk, v, 3, UID), UID)) == 5


def test_legacy_unpadded_blob_still_opens():
    vk = generate_vault_key()
    v = vault_with(2)
    nonce, ct = aead.encrypt(vk, v.to_bytes(), vault_aad(1, UID))  # formato anterior
    assert len(open_vault(vk, SealedVault(1, nonce, ct), UID)) == 2


def test_bad_padding_rejected():
    with pytest.raises(PaddingError):
        unpad(pad(b"hola")[:-1] + b"\x01")  # basura después del relleno
    with pytest.raises(PaddingError):
        unpad(b"\x01\x00\x00\x10\x00ab")  # longitud mayor al contenido


# --------------------------------------------------------------------------- #
# Respaldo cifrado
# --------------------------------------------------------------------------- #
def test_export_import_roundtrip():
    v = vault_with(3)
    data = export_vault(v, BACKUP_PW, FAST_PARAMS)
    entries = import_vault(data, BACKUP_PW)
    assert sorted((e.service, e.password) for e in entries) == sorted(
        (e.service, e.password) for e in v.all()
    )


def test_export_has_fresh_salt_and_nonce_and_no_plaintext():
    v = vault_with(1)
    a = json.loads(export_vault(v, BACKUP_PW, FAST_PARAMS))
    b = json.loads(export_vault(v, BACKUP_PW, FAST_PARAMS))
    assert a["kdf"]["salt"] != b["kdf"]["salt"]
    assert a["nonce"] != b["nonce"]
    raw = export_vault(v, BACKUP_PW, FAST_PARAMS)
    assert b"servicio0" not in raw and b"pw-0000" not in raw


def test_wrong_backup_password():
    data = export_vault(vault_with(1), BACKUP_PW, FAST_PARAMS)
    with pytest.raises(ExportAuthError):
        import_vault(data, "Otra-Contrasena-123")


def _tamper(data: bytes, mutate) -> bytes:
    doc = json.loads(data)
    mutate(doc)
    return json.dumps(doc).encode()


def _flip_b64(s: str) -> str:
    raw = bytearray(base64.b64decode(s))
    raw[len(raw) // 2] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(ciphertext=_flip_b64(d["ciphertext"])),
        lambda d: d.update(nonce=_flip_b64(d["nonce"])),
        lambda d: d["kdf"].update(salt=_flip_b64(d["kdf"]["salt"])),
        lambda d: d["kdf"].update(time_cost=d["kdf"]["time_cost"] + 1),
    ],
    ids=["ciphertext", "nonce", "salt", "kdf_params"],
)
def test_tampered_file_is_detected(mutate):
    data = export_vault(vault_with(2), BACKUP_PW, FAST_PARAMS)
    with pytest.raises(ExportAuthError):
        import_vault(_tamper(data, mutate), BACKUP_PW)


def test_truncated_or_foreign_file_rejected():
    data = export_vault(vault_with(1), BACKUP_PW, FAST_PARAMS)
    with pytest.raises(ExportError):
        import_vault(data[: len(data) // 2], BACKUP_PW)
    with pytest.raises(ExportError):
        import_vault(b'{"magic": "otra-cosa"}', BACKUP_PW)
    with pytest.raises(ExportError):
        import_vault(_tamper(data, lambda d: d.update(format=99)), BACKUP_PW)


def test_weak_params_in_file_rejected():
    data = export_vault(vault_with(1), BACKUP_PW, FAST_PARAMS)
    weak = _tamper(data, lambda d: d["kdf"].update(memory_kib=8, time_cost=1))
    with pytest.raises(ExportError, match="inseguros"):
        import_vault(weak, BACKUP_PW)


def test_passkeys_are_not_exported():
    from client.vault.models import Passkey

    v = vault_with(1)
    v.add_passkey(Passkey(credential_id=1, label="laptop", private_key="c2VjcmV0", public_key="cHVi"))
    entries = import_vault(export_vault(v, BACKUP_PW, FAST_PARAMS), BACKUP_PW)
    assert len(entries) == 1


# --------------------------------------------------------------------------- #
# Integración con VaultManager
# --------------------------------------------------------------------------- #
def test_manager_export_then_import_into_other_account(manager_factory, tmp_path):
    a = manager_factory()
    a.register("a@utec.edu.pe", "Tr3s-Tristes-Tigres!")
    a.vault.add(Entry(service="github.com", password="hunter2"))
    a.save()
    path = tmp_path / "respaldo.pmx"
    assert a.export_backup(path, BACKUP_PW) == 1

    b = manager_factory()
    b.register("b@utec.edu.pe", "Otra-Clave-Muy-Larga-42")
    assert b.import_backup(path, BACKUP_PW) == 1
    assert b.version == 2  # se subió al servidor
    assert b.vault.all()[0].password == "hunter2"
    # Importar dos veces el mismo respaldo no duplica entradas idénticas.
    assert b.import_backup(path, BACKUP_PW) == 0
    assert len(b.vault) == 1


def test_manager_import_conflicting_id_adds_copy(manager_factory, tmp_path):
    m = manager_factory()
    m.register("a@utec.edu.pe", "Tr3s-Tristes-Tigres!")
    e = m.vault.add(Entry(service="github.com", password="v1"))
    m.save()
    path = tmp_path / "r.pmx"
    m.export_backup(path, BACKUP_PW)
    m.vault.update(e.id, password="v2")
    m.save()
    assert m.import_backup(path, BACKUP_PW) == 1
    assert sorted(x.password for x in m.vault.all()) == ["v1", "v2"]


def test_manager_rejects_weak_backup_password(manager_factory, tmp_path):
    m = manager_factory()
    m.register("a@utec.edu.pe", "Tr3s-Tristes-Tigres!")
    from client.vault.manager import WeakMasterPasswordError

    with pytest.raises(WeakMasterPasswordError, match="respaldo"):
        m.export_backup(tmp_path / "r.pmx", "corta")
