"""Cifrado autenticado con XChaCha20-Poly1305 (libsodium vía PyNaCl).

Decisión de API: `encrypt` NO acepta un nonce como argumento. Siempre genera uno
nuevo de 192 bits con el CSPRNG del SO y lo devuelve. Así es imposible, por
construcción, reutilizar un nonce desde el código de la aplicación.
Con 192 bits la probabilidad de colisión de nonces aleatorios es despreciable
(~2^-96 tras 2^48 cifrados con la misma llave), a diferencia de los 96 bits de AES-GCM.
"""

from __future__ import annotations

import secrets
import struct

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_ABYTES,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
)
from nacl.exceptions import CryptoError

KEY_SIZE = crypto_aead_xchacha20poly1305_ietf_KEYBYTES  # 32
NONCE_SIZE = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24
TAG_SIZE = crypto_aead_xchacha20poly1305_ietf_ABYTES  # 16


class DecryptionError(Exception):
    """El tag Poly1305 no valida: llave incorrecta, AAD distinto o datos alterados."""


def encode_aad(*fields: bytes) -> bytes:
    """Codifica varios campos con prefijo de longitud (sin ambigüedad de concatenación).

    Sin el prefijo, ("ab", "c") y ("a", "bc") producirían el mismo AAD.
    """
    out = bytearray()
    for f in fields:
        out += struct.pack(">I", len(f))
        out += f
    return bytes(out)


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Devuelve (nonce, ciphertext||tag). El nonce es fresco en cada llamada."""
    if len(key) != KEY_SIZE:
        raise ValueError("La llave debe tener 32 bytes")
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    return nonce, ct


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError("La llave debe tener 32 bytes")
    if len(nonce) != NONCE_SIZE:
        raise DecryptionError("Nonce de tamaño inválido")
    if len(ciphertext) < TAG_SIZE:
        raise DecryptionError("Ciphertext demasiado corto")
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)
    except CryptoError as exc:
        raise DecryptionError("Fallo de autenticación AEAD") from exc
