"""Sellado de la bóveda completa como un blob AEAD.

    blob = XChaCha20-Poly1305(VK, pad(JSON(bóveda)), nonce_b, AAD = "vault" || versión(u64) || user_id)

La versión va dentro del AAD: si el servidor devuelve un blob antiguo diciendo
que es otra versión, el tag no valida. El user_id en el AAD impide que el blob
de un usuario se presente como el de otro.

Padding: XChaCha20-Poly1305 es un cifrado de flujo, así que |ciphertext| = |texto| + 16.
Sin relleno, el servidor (o quien vea el tráfico) podría estimar cuántas entradas hay
y notar cada alta o baja por el cambio de tamaño. Por eso el texto se rellena a un
múltiplo de `PAD_BLOCK` ANTES de cifrar:

    pad(x) = 0x01 || len(x) (u32, big-endian) || x || 0x00 ... 0x00     (múltiplo de PAD_BLOCK)

El relleno queda dentro del AEAD (autenticado). El byte 0x01 marca el formato con
relleno; un JSON nunca empieza con 0x01, así que los blobs viejos sin relleno
(que empiezan con '{') se siguen abriendo.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from client.crypto import aead

from .models import Vault

VAULT_LABEL = b"vault"

PAD_BLOCK = 4096  # bytes; ~15-20 entradas típicas caben en un mismo bloque
_PAD_MARKER = 0x01
_PAD_HEADER = struct.Struct(">BI")  # marcador + longitud real


class PaddingError(ValueError):
    """El relleno no es válido (sólo puede pasar con un texto que ya pasó el tag AEAD)."""


def pad(data: bytes, block: int = PAD_BLOCK) -> bytes:
    body = _PAD_HEADER.pack(_PAD_MARKER, len(data)) + data
    return body + b"\x00" * (-len(body) % block)


def unpad(padded: bytes) -> bytes:
    if not padded or padded[0] != _PAD_MARKER:
        # Bóveda sellada antes de que existiera el padding: es el JSON tal cual.
        return padded
    if len(padded) < _PAD_HEADER.size:
        raise PaddingError("Relleno truncado")
    _, length = _PAD_HEADER.unpack_from(padded)
    end = _PAD_HEADER.size + length
    if end > len(padded) or any(padded[end:]):
        raise PaddingError("Relleno inválido")
    return padded[_PAD_HEADER.size : end]


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
    nonce, ct = aead.encrypt(vk, pad(vault.to_bytes()), vault_aad(version, user_id))
    return SealedVault(version=version, nonce=nonce, ciphertext=ct)


def open_vault(vk: bytes, sealed: SealedVault, user_id: str) -> Vault:
    """Lanza aead.DecryptionError si el blob fue alterado o la versión no coincide."""
    plaintext = aead.decrypt(
        vk, sealed.nonce, sealed.ciphertext, vault_aad(sealed.version, user_id)
    )
    return Vault.from_bytes(unpad(plaintext))
