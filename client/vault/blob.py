"""Sellado de la bóveda completa como un blob AEAD.

    blob = XChaCha20-Poly1305(VK, JSON(bóveda), nonce_b, AAD = "vault" || versión(u64) || user_id)

La versión va dentro del AAD: si el servidor devuelve un blob antiguo diciendo
que es otra versión, el tag no valida. El user_id en el AAD impide que el blob
de un usuario se presente como el de otro.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from client.crypto import aead

from .models import Vault

VAULT_LABEL = b"vault"


@dataclass(frozen=True)
class SealedVault:
    version: int
    nonce: bytes
    ciphertext: bytes


def vault_aad(version: int, user_id: str) -> bytes:
    if version < 1:
        raise ValueError("La versión debe ser ≥ 1")
    return aead.encode_aad(VAULT_LABEL, struct.pack(">Q", version), user_id.encode("utf-8"))


def seal_vault(vk: bytes, vault: Vault, version: int, user_id: str) -> SealedVault:
    nonce, ct = aead.encrypt(vk, vault.to_bytes(), vault_aad(version, user_id))
    return SealedVault(version=version, nonce=nonce, ciphertext=ct)


def open_vault(vk: bytes, sealed: SealedVault, user_id: str) -> Vault:
    """Lanza aead.DecryptionError si el blob fue alterado o la versión no coincide."""
    plaintext = aead.decrypt(
        vk, sealed.nonce, sealed.ciphertext, vault_aad(sealed.version, user_id)
    )
    return Vault.from_bytes(plaintext)
