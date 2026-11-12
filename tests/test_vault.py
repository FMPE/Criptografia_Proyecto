from __future__ import annotations

import pytest

from client.crypto import aead
from client.crypto.keys import generate_vault_key
from client.vault.blob import SealedVault, open_vault, seal_vault
from client.vault.models import Entry, Vault


def sample_vault() -> Vault:
    v = Vault()
    v.add(Entry(service="github.com", username="franco", password="x1", tags=["trabajo"]))
    v.add(Entry(service="gmail.com", username="franco@gmail.com", password="x2", tags=["personal"]))
    v.add(Entry(service="utec.edu.pe", username="fpacheco", password="x3", notes="campus"))
    return v


def test_crud():
    v = sample_vault()
    e = v.search("github")[0]
    v.update(e.id, password="nueva")
    assert v.get(e.id).password == "nueva"
    dup = v.duplicate(e.id)
    assert dup.id != e.id and dup.password == "nueva"
    v.delete(e.id)
    with pytest.raises(KeyError):
        v.get(e.id)
    assert len(v) == 3


def test_service_required():
    with pytest.raises(ValueError):
        Vault().add(Entry(service="  "))


def test_search_and_tags():
    v = sample_vault()
    assert [e.service for e in v.search("GMAIL")] == ["gmail.com"]
    assert [e.service for e in v.search("campus")] == ["utec.edu.pe"]
    assert [e.service for e in v.search(tag="trabajo")] == ["github.com"]
    assert len(v.search("")) == 3
    assert v.tags() == ["personal", "trabajo"]


def test_serialization_roundtrip():
    v = sample_vault()
    v2 = Vault.from_bytes(v.to_bytes())
    assert [e.__dict__ for e in v2.all()] == [e.__dict__ for e in v.all()]


def test_seal_open_roundtrip():
    vk = generate_vault_key()
    sealed = seal_vault(vk, sample_vault(), 7, "a@b.c")
    assert b"github" not in sealed.ciphertext
    assert len(open_vault(vk, sealed, "a@b.c")) == 3


def test_version_is_authenticated():
    """Cambiar la versión declarada (rollback/replay) invalida el tag."""
    vk = generate_vault_key()
    sealed = seal_vault(vk, sample_vault(), 3, "a@b.c")
    for forged in (2, 4):
        with pytest.raises(aead.DecryptionError):
            open_vault(vk, SealedVault(forged, sealed.nonce, sealed.ciphertext), "a@b.c")


def test_blob_bound_to_user():
    vk = generate_vault_key()
    sealed = seal_vault(vk, sample_vault(), 1, "a@b.c")
    with pytest.raises(aead.DecryptionError):
        open_vault(vk, sealed, "otro@b.c")
