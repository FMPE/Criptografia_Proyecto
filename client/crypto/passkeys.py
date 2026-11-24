"""Passkeys Ed25519 con challenge-response (estilo SSH, ante nuestro propio servidor).

    (sk, pk)  = Ed25519.generate()
    sk        se guarda DENTRO de la bóveda (cifrada bajo VK); el servidor nunca la ve
    pk        se registra en el servidor (no es secreta)
    login:    sig = Ed25519.sign(sk, enc("pm-passkey-auth-v1", email, challenge_id, challenge))

Los mensajes firmados llevan una etiqueta de dominio y se codifican con prefijo de
longitud (`aead.encode_aad`): una firma de registro nunca vale como firma de login, y
una firma para un usuario/challenge no vale para otro.

Ed25519 es determinista (RFC 8032): no necesita aleatoriedad por firma, a
diferencia de ECDSA, donde un nonce repetido o sesgado filtra la llave privada.
"""

from __future__ import annotations

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from .aead import encode_aad

SEED_SIZE = 32
PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64
CHALLENGE_SIZE = 32

AUTH_LABEL = b"pm-passkey-auth-v1"
REGISTER_LABEL = b"pm-passkey-register-v1"


def generate_keypair() -> tuple[bytes, bytes]:
    """Devuelve (seed de 32 B, llave pública de 32 B). La seed ES la llave privada."""
    sk = SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def public_key_from_seed(seed: bytes) -> bytes:
    return bytes(SigningKey(seed).verify_key)


def auth_message(email: str, challenge_id: str, challenge: bytes) -> bytes:
    if len(challenge) != CHALLENGE_SIZE:
        raise ValueError("El challenge debe tener 32 bytes")
    return encode_aad(
        AUTH_LABEL, email.encode("utf-8"), challenge_id.encode("ascii"), challenge
    )


def registration_message(email: str, public_key: bytes) -> bytes:
    """Prueba de posesión: quien registra una pública demuestra tener su privada."""
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise ValueError("La llave pública debe tener 32 bytes")
    return encode_aad(REGISTER_LABEL, email.encode("utf-8"), public_key)


def sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != SEED_SIZE:
        raise ValueError("La llave privada debe tener 32 bytes")
    return SigningKey(seed).sign(message).signature


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        VerifyKey(public_key).verify(message, signature)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False
