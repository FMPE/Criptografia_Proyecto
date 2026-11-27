"""Exportación e importación cifrada de la bóveda (archivo de respaldo `.pmx`).

El respaldo NO depende de la cuenta: no usa VK, ni la Secret Key, ni la contraseña
maestra. Se protege con una contraseña de respaldo propia, así se puede guardar en
un USB o restaurar en otra cuenta.

    salt   = 16 B aleatorios (nuevos en cada exportación)
    K_exp  = HKDF-Expand(Argon2id(contraseña_respaldo, salt), info="pm-export-v1")
    AAD    = enc("pm-export-v1", formato(u32), m(u32), t(u32), p(u32), salt)
    ct     = XChaCha20-Poly1305(K_exp, pad(JSON(entradas)), nonce nuevo de 24 B, AAD)

El archivo es un JSON con: magic, formato, parámetros de Argon2id, salt, nonce y ct.
Todo el encabezado entra en el AAD: cambiar un parámetro, el salt o el formato hace
fallar el tag igual que cambiar un byte del ciphertext.

Contenido: sólo las entradas. Las passkeys NO se exportan: su llave privada sólo sirve
para la cuenta (y el servidor) donde se registró, y sacarla de la bóveda sólo agrega
exposición.
"""

from __future__ import annotations

import base64
import json
import secrets
import struct
from dataclasses import asdict

from argon2.low_level import Type, hash_secret_raw

from client.crypto import aead
from client.crypto.kdf import (
    SALT_KDF_SIZE,
    KdfParams,
    check_params,
    hkdf_expand,
    normalize_password,
)

from .blob import PaddingError, pad, unpad
from .models import Entry, Vault

EXPORT_MAGIC = "pm-export"
EXPORT_FORMAT = 1
EXPORT_LABEL = b"pm-export-v1"
EXPORT_EXTENSION = "pmx"
MAX_EXPORT_BYTES = 16 * 1024 * 1024


class ExportError(ValueError):
    """El archivo no es un respaldo válido (formato desconocido o mal formado)."""


class ExportAuthError(ExportError):
    """Contraseña de respaldo incorrecta o archivo alterado (no se pueden distinguir)."""


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def _aad(fmt: int, params: KdfParams, salt: bytes) -> bytes:
    return aead.encode_aad(
        EXPORT_LABEL,
        struct.pack(">IIII", fmt, params.memory_kib, params.time_cost, params.parallelism),
        salt,
    )


def _derive(password: str, salt: bytes, params: KdfParams) -> bytes:
    if not password:
        raise ValueError("La contraseña de respaldo no puede estar vacía")
    stretched = hash_secret_raw(
        secret=normalize_password(password),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=32,
        type=Type.ID,
    )
    return hkdf_expand(stretched, EXPORT_LABEL)


def export_vault(vault: Vault, password: str, params: KdfParams) -> bytes:
    """Devuelve los bytes del archivo de respaldo cifrado."""
    check_params(params)
    salt = secrets.token_bytes(SALT_KDF_SIZE)
    key = _derive(password, salt, params)
    doc = {"format": EXPORT_FORMAT, "entries": [asdict(e) for e in vault.all()]}
    plaintext = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    nonce, ct = aead.encrypt(key, pad(plaintext), _aad(EXPORT_FORMAT, params, salt))
    out = {
        "magic": EXPORT_MAGIC,
        "format": EXPORT_FORMAT,
        "kdf": {"alg": "argon2id", **params.to_dict(), "salt": _b64(salt)},
        "nonce": _b64(nonce),
        "ciphertext": _b64(ct),
    }
    return json.dumps(out, indent=2).encode("utf-8")


def import_vault(data: bytes, password: str) -> list[Entry]:
    """Descifra un respaldo y devuelve sus entradas.

    Lanza ExportError si el archivo no tiene el formato esperado y ExportAuthError
    si la contraseña es incorrecta o el archivo fue modificado.
    """
    if len(data) > MAX_EXPORT_BYTES:
        raise ExportError("El archivo es demasiado grande para ser un respaldo")
    try:
        doc = json.loads(data.decode("utf-8"))
        if doc.get("magic") != EXPORT_MAGIC:
            raise ExportError("No es un respaldo de este gestor")
        fmt = int(doc["format"])
        kdf = doc["kdf"]
        if kdf.get("alg") != "argon2id":
            raise ExportError("Algoritmo de derivación no soportado")
        params = KdfParams.from_dict(kdf)
        salt = _unb64(kdf["salt"])
        nonce = _unb64(doc["nonce"])
        ct = _unb64(doc["ciphertext"])
    except ExportError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ExportError("Archivo de respaldo mal formado") from exc
    if fmt != EXPORT_FORMAT:
        raise ExportError(f"Formato de respaldo no soportado: {fmt}")
    if len(salt) != SALT_KDF_SIZE:
        raise ExportError("Salt de tamaño inválido")
    # Un archivo fabricado con parámetros ridículos no debe abaratar el ataque ni
    # colgar el cliente con un costo enorme.
    try:
        check_params(params)
    except ValueError as exc:
        raise ExportError(f"Respaldo con parámetros inseguros: {exc}") from exc
    if params.memory_kib > 4 * 1024 * 1024 or params.time_cost > 20 or params.parallelism > 16:
        raise ExportError("Parámetros de Argon2id fuera de rango")

    key = _derive(password, salt, params)
    try:
        plaintext = unpad(aead.decrypt(key, nonce, ct, _aad(fmt, params, salt)))
        inner = json.loads(plaintext.decode("utf-8"))
        if inner.get("format") != EXPORT_FORMAT:
            raise ExportError("Contenido del respaldo no soportado")
        return [Entry.from_dict(e) for e in inner["entries"]]
    except ExportError:
        raise
    except aead.DecryptionError as exc:
        raise ExportAuthError("Contraseña de respaldo incorrecta o archivo alterado") from exc
    except (PaddingError, ValueError, KeyError, TypeError) as exc:
        raise ExportError("Contenido del respaldo mal formado") from exc
