"""Configuración del servidor (por variables de entorno)."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


@dataclass
class Settings:
    database_url: str = field(
        default_factory=lambda: os.environ.get("PM_DATABASE_URL", "sqlite:///./server.db")
    )
    # Argon2id del lado servidor sobre AuthKey (Argon2id(AuthKey, salt_srv)).
    argon2_memory_kib: int = field(default_factory=lambda: _int("PM_ARGON2_MEMORY_KIB", 64 * 1024))
    argon2_time_cost: int = field(default_factory=lambda: _int("PM_ARGON2_TIME_COST", 3))
    argon2_parallelism: int = field(default_factory=lambda: _int("PM_ARGON2_PARALLELISM", 4))

    token_ttl_seconds: int = field(default_factory=lambda: _int("PM_TOKEN_TTL", 15 * 60))
    login_max_failures: int = field(default_factory=lambda: _int("PM_LOGIN_MAX_FAILURES", 5))
    login_window_seconds: int = field(default_factory=lambda: _int("PM_LOGIN_WINDOW", 5 * 60))
    max_blob_bytes: int = field(default_factory=lambda: _int("PM_MAX_BLOB_BYTES", 5 * 1024 * 1024))

    # Llave para generar salts falsos deterministas en /kdf-params ante correos
    # inexistentes (evita enumerar usuarios). Debe ser estable entre reinicios.
    fake_salt_key: bytes = field(
        default_factory=lambda: bytes.fromhex(os.environ["PM_FAKE_SALT_KEY"])
        if "PM_FAKE_SALT_KEY" in os.environ
        else secrets.token_bytes(32)
    )

    # Mínimos aceptados en el registro (validación de cordura, el cliente también lo hace).
    min_client_memory_kib: int = field(default_factory=lambda: _int("PM_MIN_CLIENT_MEMORY_KIB", 64 * 1024))
    min_client_time_cost: int = field(default_factory=lambda: _int("PM_MIN_CLIENT_TIME_COST", 3))
