"""Almacén local del cliente.

Estructura (por usuario, en ~/.pwmanager/<sha256(email)[:16]>/):
    secret_key     32 B en crudo, permisos 0600
    account.json   email, salt_kdf, parámetros de Argon2id (no secretos)
    cache.json     el mismo blob cifrado + VK envuelta que guarda el servidor

Nada de lo que se escribe aquí está en claro salvo la Secret Key, que es
precisamente el "secreto guardado en el cliente". La caché está cifrada igual
que en el servidor, por lo que permite desbloquear sin conexión.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from client.crypto.kdf import SECRET_KEY_SIZE, KdfParams
from client.crypto.keys import WrappedKey

from .blob import SealedVault


def default_home() -> Path:
    return Path(os.environ.get("PM_HOME", Path.home() / ".pwmanager"))


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def _write_private(path: Path, data: bytes) -> None:
    """Escritura atómica con permisos 0600 (en Windows, la ACL del perfil de usuario)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


@dataclass
class AccountInfo:
    email: str
    salt_kdf: bytes
    kdf_params: KdfParams


@dataclass
class CachedVault:
    sealed: SealedVault
    wrapped_vk: WrappedKey
    pending: bool = False  # cambios locales aún no subidos al servidor


class LocalStore:
    def __init__(self, email: str, home: Path | None = None) -> None:
        digest = hashlib.sha256(email.encode("utf-8")).hexdigest()[:16]
        self.dir = (home or default_home()) / digest
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.dir, 0o700)
        except OSError:  # pragma: no cover - depende del SO
            pass

    # ---- Secret Key ------------------------------------------------------- #
    @property
    def _sk_path(self) -> Path:
        return self.dir / "secret_key"

    def has_secret_key(self) -> bool:
        return self._sk_path.exists()

    def save_secret_key(self, sk: bytes) -> None:
        if len(sk) != SECRET_KEY_SIZE:
            raise ValueError("Secret Key inválida")
        _write_private(self._sk_path, sk)

    def load_secret_key(self) -> bytes:
        sk = self._sk_path.read_bytes()
        if len(sk) != SECRET_KEY_SIZE:
            raise ValueError("Archivo de Secret Key corrupto")
        return sk

    # ---- Cuenta ----------------------------------------------------------- #
    def save_account(self, info: AccountInfo) -> None:
        doc = {
            "email": info.email,
            "salt_kdf": _b64(info.salt_kdf),
            "kdf_params": info.kdf_params.to_dict(),
        }
        _write_private(self.dir / "account.json", json.dumps(doc).encode())

    def load_account(self) -> AccountInfo | None:
        path = self.dir / "account.json"
        if not path.exists():
            return None
        doc = json.loads(path.read_text("utf-8"))
        return AccountInfo(
            email=doc["email"],
            salt_kdf=_unb64(doc["salt_kdf"]),
            kdf_params=KdfParams.from_dict(doc["kdf_params"]),
        )

    # ---- Caché cifrada ---------------------------------------------------- #
    def save_cache(self, cache: CachedVault) -> None:
        doc = {
            "version": cache.sealed.version,
            "nonce": _b64(cache.sealed.nonce),
            "ciphertext": _b64(cache.sealed.ciphertext),
            "wrapped_vk": {
                "nonce": _b64(cache.wrapped_vk.nonce),
                "ciphertext": _b64(cache.wrapped_vk.ciphertext),
            },
            "pending": cache.pending,
        }
        _write_private(self.dir / "cache.json", json.dumps(doc).encode())

    def load_cache(self) -> CachedVault | None:
        path = self.dir / "cache.json"
        if not path.exists():
            return None
        doc = json.loads(path.read_text("utf-8"))
        return CachedVault(
            sealed=SealedVault(
                version=int(doc["version"]),
                nonce=_unb64(doc["nonce"]),
                ciphertext=_unb64(doc["ciphertext"]),
            ),
            wrapped_vk=WrappedKey(
                nonce=_unb64(doc["wrapped_vk"]["nonce"]),
                ciphertext=_unb64(doc["wrapped_vk"]["ciphertext"]),
            ),
            pending=bool(doc.get("pending", False)),
        )
