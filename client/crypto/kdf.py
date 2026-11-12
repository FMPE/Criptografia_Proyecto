"""Derivación de llaves del cliente.

    salt     = HKDF-Extract(salt_kdf, SecretKey)            (RFC 5869, HMAC-SHA-256)
    MK       = Argon2id(contraseña_maestra, salt)           (m=64 MiB, t=3, p=4, 32 B)
    AuthKey  = HKDF-Expand(MK, info="auth",      L=32)
    KEK      = HKDF-Expand(MK, info="vault-kek", L=32)

La Secret Key no se concatena a la contraseña: se mezcla en el salt, de modo que
Argon2id ya trabaja sobre un salt de 256 bits que el servidor nunca conoce.
Los `info` distintos dan separación de dominio: conocer AuthKey (que sí viaja al
servidor) no revela nada sobre KEK.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

KEY_SIZE = 32
SALT_KDF_SIZE = 16
SECRET_KEY_SIZE = 32

INFO_AUTH = b"auth"
INFO_KEK = b"vault-kek"


class WeakKdfParamsError(ValueError):
    """Los parámetros de Argon2 recibidos están por debajo del mínimo aceptado."""


@dataclass(frozen=True)
class KdfParams:
    memory_kib: int = 64 * 1024  # 64 MiB
    time_cost: int = 3
    parallelism: int = 4

    def to_dict(self) -> dict:
        return {
            "memory_kib": self.memory_kib,
            "time_cost": self.time_cost,
            "parallelism": self.parallelism,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "KdfParams":
        return cls(
            memory_kib=int(data["memory_kib"]),
            time_cost=int(data["time_cost"]),
            parallelism=int(data["parallelism"]),
        )


DEFAULT_PARAMS = KdfParams()

# Mínimo que el cliente acepta. Los parámetros llegan del servidor (no confiable)
# en un dispositivo nuevo: un servidor malicioso podría bajar el costo para
# facilitar la fuerza bruta, así que el cliente se niega a derivar por debajo de esto.
MIN_PARAMS = KdfParams(memory_kib=64 * 1024, time_cost=3, parallelism=1)


def check_params(params: KdfParams, minimum: KdfParams | None = None) -> None:
    minimum = minimum or MIN_PARAMS
    if params.memory_kib < minimum.memory_kib or params.time_cost < minimum.time_cost:
        raise WeakKdfParamsError(
            f"Parámetros Argon2id demasiado débiles: {params} (mínimo {minimum})"
        )
    if params.parallelism < minimum.parallelism:
        raise WeakKdfParamsError(f"Paralelismo inválido: {params.parallelism}")


@dataclass(frozen=True)
class DerivedKeys:
    auth_key: bytes  # se envía al servidor (sobre TLS)
    kek: bytes  # nunca sale del cliente; envuelve a VK


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract(salt, IKM) = HMAC-SHA-256(key=salt, msg=IKM)  (RFC 5869 §2.2)."""
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()


def hkdf_expand(prk: bytes, info: bytes, length: int = KEY_SIZE) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(prk)


def normalize_password(password: str) -> bytes:
    # NFKC: la misma contraseña escrita en otro teclado/SO produce los mismos bytes.
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def derive_master_key(
    password: str, secret_key: bytes, salt_kdf: bytes, params: KdfParams
) -> bytes:
    if len(secret_key) != SECRET_KEY_SIZE:
        raise ValueError("La Secret Key debe tener 32 bytes")
    if len(salt_kdf) != SALT_KDF_SIZE:
        raise ValueError("salt_kdf debe tener 16 bytes")
    if not password:
        raise ValueError("La contraseña maestra no puede estar vacía")

    salt = hkdf_extract(salt_kdf, secret_key)
    return hash_secret_raw(
        secret=normalize_password(password),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def derive_keys(
    password: str,
    secret_key: bytes,
    salt_kdf: bytes,
    params: KdfParams = DEFAULT_PARAMS,
) -> DerivedKeys:
    mk = derive_master_key(password, secret_key, salt_kdf, params)
    keys = DerivedKeys(
        auth_key=hkdf_expand(mk, INFO_AUTH),
        kek=hkdf_expand(mk, INFO_KEK),
    )
    # MK no se guarda ni se devuelve. (En Python no se puede garantizar el borrado
    # de un objeto `bytes` inmutable; ver limitaciones en el informe.)
    del mk
    return keys
