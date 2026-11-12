"""Orquestación de los flujos criptográficos del cliente: registro, desbloqueo y guardado.

Este módulo es la única pieza que junta llaves, bóveda, almacén local y red.
La UI sólo habla con `VaultManager`.
"""

from __future__ import annotations

from pathlib import Path

from client.crypto import aead
from client.crypto.generator import estimate_password_entropy
from client.crypto.kdf import DEFAULT_PARAMS, KdfParams, check_params, derive_keys
from client.crypto.keys import (
    format_secret_key,
    generate_salt_kdf,
    generate_secret_key,
    generate_vault_key,
    parse_secret_key,
    unwrap_vault_key,
    wrap_vault_key,
)
from client.net.api_client import ApiClient, AuthError, ConflictError, NetworkError

from .blob import SealedVault, open_vault, seal_vault
from .models import Vault
from .storage import AccountInfo, CachedVault, LocalStore

MIN_MASTER_LENGTH = 12
MIN_MASTER_ENTROPY_BITS = 50.0


class VaultError(Exception):
    pass


class WeakMasterPasswordError(VaultError):
    pass


class SecretKeyRequiredError(VaultError):
    """Dispositivo nuevo: no hay Secret Key local y hay que transcribirla."""


class WrongCredentialsError(VaultError):
    pass


class VaultLockedError(VaultError):
    pass


class OfflineError(VaultError):
    pass


class SyncConflictError(VaultError):
    pass


class SessionExpiredError(VaultError):
    pass


class IntegrityError(VaultError):
    """El blob no pasó la verificación AEAD: fue alterado o no corresponde."""


def normalize_email(email: str) -> str:
    email = email.strip().lower()
    if "@" not in email or len(email) > 254:
        raise ValueError("Correo inválido")
    return email


def check_master_password(password: str) -> None:
    if len(password) < MIN_MASTER_LENGTH:
        raise WeakMasterPasswordError(
            f"La contraseña maestra debe tener al menos {MIN_MASTER_LENGTH} caracteres"
        )
    if estimate_password_entropy(password) < MIN_MASTER_ENTROPY_BITS:
        raise WeakMasterPasswordError("La contraseña maestra es demasiado predecible")


class VaultManager:
    def __init__(
        self,
        api: ApiClient,
        home: Path | None = None,
        kdf_params: KdfParams = DEFAULT_PARAMS,
    ) -> None:
        self.api = api
        self.home = home
        self.kdf_params = kdf_params
        self._reset()

    def _reset(self) -> None:
        self.email: str | None = None
        self.store: LocalStore | None = None
        self.vault: Vault | None = None
        self.version: int = 0
        self.online: bool = False
        self._vk: bytes | None = None
        self._wrapped_vk = None

    @property
    def is_unlocked(self) -> bool:
        return self._vk is not None and self.vault is not None

    # ------------------------------------------------------------------ #
    # Registro
    # ------------------------------------------------------------------ #
    def register(self, email: str, password: str) -> str:
        """Crea la cuenta. Devuelve la Secret Key formateada (se muestra UNA vez)."""
        email = normalize_email(email)
        check_master_password(password)

        secret_key = generate_secret_key()
        salt_kdf = generate_salt_kdf()
        keys = derive_keys(password, secret_key, salt_kdf, self.kdf_params)

        vk = generate_vault_key()
        wrapped = wrap_vault_key(keys.kek, vk, email)
        vault = Vault()
        sealed = seal_vault(vk, vault, version=1, user_id=email)

        self.api.register(email, salt_kdf, self.kdf_params, keys.auth_key, wrapped, sealed)

        store = LocalStore(email, self.home)
        store.save_secret_key(secret_key)
        store.save_account(AccountInfo(email, salt_kdf, self.kdf_params))
        store.save_cache(CachedVault(sealed=sealed, wrapped_vk=wrapped))

        self.email, self.store, self.vault = email, store, vault
        self.version, self.online = 1, True
        self._vk, self._wrapped_vk = vk, wrapped
        return format_secret_key(secret_key)

    # ------------------------------------------------------------------ #
    # Desbloqueo
    # ------------------------------------------------------------------ #
    def unlock(self, email: str, password: str, secret_key_text: str | None = None) -> None:
        email = normalize_email(email)
        store = LocalStore(email, self.home)

        new_device = not store.has_secret_key()
        if not new_device:
            secret_key = store.load_secret_key()
        elif secret_key_text:
            secret_key = parse_secret_key(secret_key_text)
        else:
            raise SecretKeyRequiredError("Este dispositivo no tiene la Secret Key")

        account = store.load_account()
        try:
            salt_kdf, params = self.api.get_kdf_params(email)
            online = True
        except NetworkError:
            if account is None:
                raise OfflineError("Sin conexión y sin datos locales de esta cuenta")
            salt_kdf, params, online = account.salt_kdf, account.kdf_params, False

        # Los parámetros pueden venir de un servidor no confiable.
        check_params(params)
        keys = derive_keys(password, secret_key, salt_kdf, params)

        if online:
            try:
                self.api.login(email, keys.auth_key)
            except AuthError:
                raise WrongCredentialsError("Contraseña maestra o Secret Key incorrectas")
            sealed, wrapped = self.api.get_vault()
        else:
            cache = store.load_cache()
            if cache is None:
                raise OfflineError("No hay copia local de la bóveda")
            sealed, wrapped = cache.sealed, cache.wrapped_vk

        try:
            vk = unwrap_vault_key(keys.kek, wrapped, email)
        except aead.DecryptionError:
            raise WrongCredentialsError("Contraseña maestra o Secret Key incorrectas")
        try:
            vault = open_vault(vk, sealed, email)
        except aead.DecryptionError:
            raise IntegrityError("La bóveda no pasó la verificación de integridad")

        # Sólo se persiste en disco lo que ya se verificó criptográficamente.
        if new_device:
            store.save_secret_key(secret_key)
        store.save_account(AccountInfo(email, salt_kdf, params))
        if online:
            store.save_cache(CachedVault(sealed=sealed, wrapped_vk=wrapped))

        self.email, self.store, self.vault = email, store, vault
        self.version, self.online = sealed.version, online
        self._vk, self._wrapped_vk = vk, wrapped

    # ------------------------------------------------------------------ #
    # Sincronización
    # ------------------------------------------------------------------ #
    def _require_unlocked(self) -> None:
        if not self.is_unlocked:
            raise VaultLockedError("La bóveda está bloqueada")

    def save(self) -> int:
        """Re-cifra la bóveda con nonce nuevo y versión+1, y la sube al servidor."""
        self._require_unlocked()
        if not self.online:
            raise OfflineError("Modo sin conexión: la bóveda es de sólo lectura")

        sealed = seal_vault(self._vk, self.vault, self.version + 1, self.email)
        try:
            self.api.put_vault(sealed)
        except ConflictError:
            raise SyncConflictError(
                "El servidor tiene una versión más reciente; recarga antes de guardar"
            )
        except AuthError:
            raise SessionExpiredError("La sesión expiró; vuelve a desbloquear")
        except NetworkError:
            raise OfflineError("No se pudo contactar al servidor")

        self.version = sealed.version
        self.store.save_cache(CachedVault(sealed=sealed, wrapped_vk=self._wrapped_vk))
        return self.version

    def pull(self) -> None:
        """Descarta cambios no guardados y carga la versión del servidor."""
        self._require_unlocked()
        try:
            sealed, wrapped = self.api.get_vault()
        except AuthError:
            raise SessionExpiredError("La sesión expiró; vuelve a desbloquear")
        except NetworkError:
            raise OfflineError("No se pudo contactar al servidor")
        try:
            self.vault = open_vault(self._vk, sealed, self.email)
        except aead.DecryptionError:
            raise IntegrityError("La bóveda no pasó la verificación de integridad")
        self.version = sealed.version
        self._wrapped_vk = wrapped
        self.store.save_cache(CachedVault(sealed=sealed, wrapped_vk=wrapped))

    def lock(self) -> None:
        """Olvida llaves y bóveda en claro. (Borrado best-effort: ver informe.)"""
        self.api.logout()
        self._reset()


__all__ = [
    "VaultManager",
    "SealedVault",
    "VaultError",
    "WeakMasterPasswordError",
    "SecretKeyRequiredError",
    "WrongCredentialsError",
    "VaultLockedError",
    "OfflineError",
    "SyncConflictError",
    "SessionExpiredError",
    "IntegrityError",
    "normalize_email",
    "check_master_password",
]
