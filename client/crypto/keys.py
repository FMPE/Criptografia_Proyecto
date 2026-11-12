"""Material de llaves: Secret Key, Vault Key (VK) y key wrapping de VK con KEK.

    VK envuelta = XChaCha20-Poly1305(KEK, VK, nonce_w, AAD = "vk-wrap" || user_id)

Con una VK intermedia, cambiar la contraseña maestra sólo re-envuelve 32 bytes
en vez de re-cifrar toda la bóveda.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

from . import aead
from .kdf import SALT_KDF_SIZE, SECRET_KEY_SIZE

VK_SIZE = 32
WRAP_LABEL = b"vk-wrap"

SECRET_KEY_PREFIX = "PM1"  # nosec B105 - prefijo de formato, no es un secreto
_CHECKSUM_SIZE = 2  # 16 bits: detecta errores de transcripción, no es un MAC
_GROUP = 5


def generate_secret_key() -> bytes:
    return secrets.token_bytes(SECRET_KEY_SIZE)


def generate_salt_kdf() -> bytes:
    return secrets.token_bytes(SALT_KDF_SIZE)


def generate_vault_key() -> bytes:
    return secrets.token_bytes(VK_SIZE)


# --------------------------------------------------------------------------- #
# Formato legible de la Secret Key (kit de emergencia)
# --------------------------------------------------------------------------- #
def _checksum(raw: bytes) -> bytes:
    return hashlib.blake2b(raw, digest_size=_CHECKSUM_SIZE, person=b"pm-secret-key").digest()


def format_secret_key(raw: bytes) -> str:
    """32 B + 2 B de checksum → Base32 (sin '=') en bloques de 5: PM1-XXXXX-XXXXX-..."""
    if len(raw) != SECRET_KEY_SIZE:
        raise ValueError("La Secret Key debe tener 32 bytes")
    b32 = base64.b32encode(raw + _checksum(raw)).decode("ascii").rstrip("=")
    groups = [b32[i : i + _GROUP] for i in range(0, len(b32), _GROUP)]
    return "-".join([SECRET_KEY_PREFIX, *groups])


class InvalidSecretKeyError(ValueError):
    pass


def parse_secret_key(text: str) -> bytes:
    cleaned = "".join(ch for ch in text.upper() if ch.isalnum())
    if not cleaned.startswith(SECRET_KEY_PREFIX):
        raise InvalidSecretKeyError("La Secret Key debe empezar con 'PM1-'")
    b32 = cleaned[len(SECRET_KEY_PREFIX) :]
    b32 += "=" * (-len(b32) % 8)
    try:
        data = base64.b32decode(b32)
    except ValueError as exc:  # binascii.Error hereda de ValueError
        raise InvalidSecretKeyError("Secret Key mal formada") from exc
    if len(data) != SECRET_KEY_SIZE + _CHECKSUM_SIZE:
        raise InvalidSecretKeyError("Longitud de Secret Key inválida")
    raw, chk = data[:SECRET_KEY_SIZE], data[SECRET_KEY_SIZE:]
    if not hmac.compare_digest(chk, _checksum(raw)):
        raise InvalidSecretKeyError("Checksum incorrecto: revisa la transcripción")
    return raw


# --------------------------------------------------------------------------- #
# Key wrapping de VK
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class WrappedKey:
    nonce: bytes
    ciphertext: bytes


def _wrap_aad(user_id: str) -> bytes:
    return aead.encode_aad(WRAP_LABEL, user_id.encode("utf-8"))


def wrap_vault_key(kek: bytes, vk: bytes, user_id: str) -> WrappedKey:
    if len(vk) != VK_SIZE:
        raise ValueError("VK debe tener 32 bytes")
    nonce, ct = aead.encrypt(kek, vk, _wrap_aad(user_id))
    return WrappedKey(nonce=nonce, ciphertext=ct)


def unwrap_vault_key(kek: bytes, wrapped: WrappedKey, user_id: str) -> bytes:
    """Lanza aead.DecryptionError si KEK es incorrecta (contraseña o Secret Key erróneas)."""
    vk = aead.decrypt(kek, wrapped.nonce, wrapped.ciphertext, _wrap_aad(user_id))
    if len(vk) != VK_SIZE:
        raise aead.DecryptionError("VK desenvuelta con tamaño inválido")
    return vk
