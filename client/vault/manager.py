"""Orquestación de los flujos criptográficos del cliente: registro, desbloqueo y guardado.

Este módulo es la única pieza que junta llaves, bóveda, almacén local y red.
La UI sólo habla con `VaultManager`.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Callable, TypeVar

from client.crypto import aead, passkeys
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
from client.net.api_client import (
    ApiClient,
    ApiError,
    AuthError,
    ConflictError,
    NetworkError,
)

from .blob import SealedVault, open_vault, seal_vault
from .models import Passkey, Vault
from .storage import AccountInfo, CachedVault, LocalStore

MIN_MASTER_LENGTH = 12
MIN_MASTER_ENTROPY_BITS = 50.0

AUTH_PASSWORD = "contraseña"  # nosec B105 - etiqueta del método de sesión, no un secreto
AUTH_PASSKEY = "passkey"
AUTH_OFFLINE = "sin conexión"

T = TypeVar("T")


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


class RollbackError(VaultError):
    """El servidor devolvió una versión más vieja que la que este dispositivo ya verificó."""


class PasskeyUnavailableError(VaultError):
    """No hay passkey utilizable (dispositivo nuevo o bóveda sin passkeys)."""


class PasskeyAuthError(VaultError):
    """El servidor rechazó la firma (passkey revocada, challenge expirado...)."""


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
        self.auth_method: str | None = None
        self._vk: bytes | None = None
        self._wrapped_vk = None

    def _set_state(self, email, store, vault, sealed: SealedVault, wrapped, vk, online, method):
        self.email, self.store, self.vault = email, store, vault
        self.version, self.online, self.auth_method = sealed.version, online, method
        self._vk, self._wrapped_vk = vk, wrapped

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
        store.record_version(sealed.version)

        self._set_state(email, store, vault, sealed, wrapped, vk, True, AUTH_PASSWORD)
        return format_secret_key(secret_key)

    # ------------------------------------------------------------------ #
    # Desbloqueo
    # ------------------------------------------------------------------ #
    def unlock(
        self,
        email: str,
        password: str,
        secret_key_text: str | None = None,
        use_passkey: bool = False,
    ) -> None:
        email = normalize_email(email)
        store = LocalStore(email, self.home)
        if use_passkey:
            self._unlock_with_passkey(email, password, store)
            return

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

        vk, vault = self._open(keys.kek, wrapped, sealed, email)
        self._check_not_rolled_back(store, sealed)

        # Sólo se persiste en disco lo que ya se verificó criptográficamente.
        if new_device:
            store.save_secret_key(secret_key)
        store.save_account(AccountInfo(email, salt_kdf, params))
        if online:
            store.save_cache(CachedVault(sealed=sealed, wrapped_vk=wrapped))

        method = AUTH_PASSWORD if online else AUTH_OFFLINE
        self._set_state(email, store, vault, sealed, wrapped, vk, online, method)

    def _unlock_with_passkey(self, email: str, password: str, store: LocalStore) -> None:
        """Desbloqueo local + login por firma Ed25519: AuthKey nunca sale del cliente.

        Sólo en un dispositivo ya usado: hacen falta la Secret Key, el salt y la
        caché locales para llegar a VK, y con VK a la llave privada de la passkey.
        """
        account, cache = store.load_account(), store.load_cache()
        if not store.has_secret_key() or account is None or cache is None:
            raise PasskeyUnavailableError(
                "La passkey sólo sirve en un dispositivo donde ya se abrió la bóveda"
            )
        check_params(account.kdf_params)
        keys = derive_keys(password, store.load_secret_key(), account.salt_kdf, account.kdf_params)
        vk, vault = self._open(keys.kek, cache.wrapped_vk, cache.sealed, email)
        self._check_not_rolled_back(store, cache.sealed)
        if vault.latest_passkey() is None:
            raise PasskeyUnavailableError("La bóveda no tiene passkeys registradas")

        self._set_state(
            email, store, vault, cache.sealed, cache.wrapped_vk, vk, False, AUTH_OFFLINE
        )
        try:
            self.login_with_passkey()
        except NetworkError:
            return  # sin conexión: queda abierta en sólo lectura desde la caché
        except (VaultError, ApiError):
            self._reset()
            raise
        self.online = True
        try:
            self.pull()  # baja la versión del servidor, la verifica y la cachea
        except RollbackError:
            self._reset()
            raise

    @staticmethod
    def _check_not_rolled_back(store: LocalStore, sealed: SealedVault) -> None:
        """Anti-rollback: rechaza versiones menores a la más alta ya verificada aquí.

        Se llama sólo DESPUÉS de validar el tag AEAD: la versión va dentro del AAD,
        así que el número ya está autenticado y el servidor no pudo cambiarlo.
        Si hay rollback no se toca nada (caché, marca de agua ni estado en memoria).
        """
        seen = store.load_max_version()
        if sealed.version < seen:
            raise RollbackError(
                f"Posible ataque de rollback: el servidor devolvió la versión v{sealed.version}, "
                f"pero este dispositivo ya verificó la v{seen}"
            )
        store.record_version(sealed.version)

    def _open(self, kek: bytes, wrapped, sealed: SealedVault, email: str) -> tuple[bytes, Vault]:
        try:
            vk = unwrap_vault_key(kek, wrapped, email)
        except aead.DecryptionError:
            raise WrongCredentialsError("Contraseña maestra o Secret Key incorrectas")
        try:
            return vk, open_vault(vk, sealed, email)
        except aead.DecryptionError:
            raise IntegrityError("La bóveda no pasó la verificación de integridad")

    # ------------------------------------------------------------------ #
    # Passkeys
    # ------------------------------------------------------------------ #
    def login_with_passkey(self) -> None:
        """Challenge-response: firma el challenge con la privada guardada en la bóveda."""
        self._require_unlocked()
        pk = self.vault.latest_passkey()
        if pk is None:
            raise PasskeyUnavailableError("La bóveda no tiene passkeys registradas")
        challenge_id, challenge = self.api.passkey_challenge(self.email)
        seed = base64.b64decode(pk.private_key)
        signature = passkeys.sign(seed, passkeys.auth_message(self.email, challenge_id, challenge))
        try:
            self.api.passkey_verify(self.email, challenge_id, pk.credential_id, signature)
        except AuthError:
            raise PasskeyAuthError("El servidor rechazó la passkey (¿fue revocada?)")
        self.auth_method = AUTH_PASSKEY

    def create_passkey(self, label: str) -> Passkey:
        """Genera un par Ed25519, registra la pública y guarda la privada en la bóveda."""
        self._require_online()
        seed, public_key = passkeys.generate_keypair()
        proof = passkeys.sign(seed, passkeys.registration_message(self.email, public_key))
        try:
            cid = self._authenticated(
                lambda: self.api.register_passkey(public_key, label, proof)
            )
        except NetworkError:
            raise OfflineError("No se pudo contactar al servidor")

        pk = Passkey(
            credential_id=cid,
            label=label,
            private_key=base64.b64encode(seed).decode("ascii"),
            public_key=base64.b64encode(public_key).decode("ascii"),
        )
        self.vault.add_passkey(pk)
        try:
            self.save()
        except VaultError:
            # Sin la privada guardada la pública registrada no sirve: se deshace.
            self.vault.remove_passkey(cid)
            try:
                self.api.delete_passkey(cid)
            except (ApiError, NetworkError):
                pass
            raise
        return pk

    def revoke_passkey(self, credential_id: int) -> None:
        self._require_online()
        try:
            self._authenticated(lambda: self.api.delete_passkey(credential_id))
        except NetworkError:
            raise OfflineError("No se pudo contactar al servidor")
        except ApiError as exc:
            if exc.status != 404:  # 404: ya estaba revocada en el servidor
                raise
        self.vault.remove_passkey(credential_id)
        self.save()

    # ------------------------------------------------------------------ #
    # Sincronización
    # ------------------------------------------------------------------ #
    def _require_unlocked(self) -> None:
        if not self.is_unlocked:
            raise VaultLockedError("La bóveda está bloqueada")

    def _require_online(self) -> None:
        self._require_unlocked()
        if not self.online:
            raise OfflineError("Modo sin conexión: la bóveda es de sólo lectura")

    def _authenticated(self, call: Callable[[], T]) -> T:
        """Ejecuta una llamada autenticada; si el token expiró, renueva con passkey y reintenta."""
        try:
            return call()
        except AuthError:
            if self.vault.latest_passkey() is None:
                raise SessionExpiredError("La sesión expiró; vuelve a desbloquear")
        try:
            self.login_with_passkey()
            return call()
        except (AuthError, PasskeyAuthError):
            raise SessionExpiredError("La sesión expiró y la passkey fue rechazada")

    def save(self) -> int:
        """Re-cifra la bóveda con nonce nuevo y versión+1, y la sube al servidor."""
        self._require_online()
        sealed = seal_vault(self._vk, self.vault, self.version + 1, self.email)
        try:
            self._authenticated(lambda: self.api.put_vault(sealed))
        except ConflictError:
            raise SyncConflictError(
                "El servidor tiene una versión más reciente; recarga antes de guardar"
            )
        except NetworkError:
            raise OfflineError("No se pudo contactar al servidor")

        self.version = sealed.version
        self.store.save_cache(CachedVault(sealed=sealed, wrapped_vk=self._wrapped_vk))
        self.store.record_version(sealed.version)
        return self.version

    def pull(self) -> None:
        """Descarta cambios no guardados y carga la versión del servidor."""
        self._require_unlocked()
        try:
            sealed, wrapped = self._authenticated(self.api.get_vault)
        except NetworkError:
            raise OfflineError("No se pudo contactar al servidor")
        try:
            vault = open_vault(self._vk, sealed, self.email)
        except aead.DecryptionError:
            raise IntegrityError("La bóveda no pasó la verificación de integridad")
        self._check_not_rolled_back(self.store, sealed)
        self.vault = vault
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
    "RollbackError",
    "PasskeyUnavailableError",
    "PasskeyAuthError",
    "normalize_email",
    "check_master_password",
]
