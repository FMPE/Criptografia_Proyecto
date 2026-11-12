"""Cliente HTTPS del servidor de sincronización.

Sólo se aceptan URLs https:// y el contexto TLS exige TLS 1.3 como mínimo.
En desarrollo se confía explícitamente en el certificado autofirmado del
servidor (`ca_cert`), no en todo el almacén de CAs del sistema.
"""

from __future__ import annotations

import base64
import ssl

import httpx

from client.crypto.kdf import KdfParams
from client.crypto.keys import WrappedKey
from client.vault.blob import SealedVault


class NetworkError(Exception):
    """No se pudo contactar al servidor (sin conexión, TLS inválido, timeout...)."""


class ApiError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail


class AuthError(ApiError):
    pass


class ConflictError(ApiError):
    pass


class RateLimitedError(ApiError):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def make_tls_context(ca_cert: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_cert)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class ApiClient:
    def __init__(
        self,
        base_url: str,
        ca_cert: str | None = None,
        http_client: httpx.Client | None = None,
        timeout: float = 15.0,
    ) -> None:
        if http_client is None:
            if not base_url.startswith("https://"):
                raise ValueError("El cliente sólo se conecta por HTTPS")
            http_client = httpx.Client(
                base_url=base_url, verify=make_tls_context(ca_cert), timeout=timeout
            )
        self._http = http_client
        self.token: str | None = None

    def close(self) -> None:
        self._http.close()

    # ------------------------------------------------------------------ #
    def _request(self, method: str, path: str, *, auth: bool = False, **kwargs) -> dict:
        headers = kwargs.pop("headers", {})
        if auth:
            if not self.token:
                raise AuthError(401, "No hay sesión iniciada")
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            resp = self._http.request(method, path, headers=headers, **kwargs)
        except httpx.TransportError as exc:
            raise NetworkError(str(exc)) from exc

        if resp.status_code < 400:
            return resp.json() if resp.content else {}

        try:
            detail = str(resp.json().get("detail", resp.text))
        except ValueError:
            detail = resp.text
        cls = {401: AuthError, 409: ConflictError, 429: RateLimitedError}.get(
            resp.status_code, ApiError
        )
        raise cls(resp.status_code, detail)

    # ------------------------------------------------------------------ #
    def register(
        self,
        email: str,
        salt_kdf: bytes,
        kdf_params: KdfParams,
        auth_key: bytes,
        wrapped_vk: WrappedKey,
        sealed: SealedVault,
    ) -> str:
        data = self._request(
            "POST",
            "/register",
            json={
                "email": email,
                "salt_kdf": _b64(salt_kdf),
                "kdf_params": kdf_params.to_dict(),
                "auth_key": _b64(auth_key),
                "wrapped_vk": {
                    "nonce": _b64(wrapped_vk.nonce),
                    "ciphertext": _b64(wrapped_vk.ciphertext),
                },
                "vault": {
                    "version": sealed.version,
                    "nonce": _b64(sealed.nonce),
                    "ciphertext": _b64(sealed.ciphertext),
                },
            },
        )
        self.token = data["token"]
        return self.token

    def get_kdf_params(self, email: str) -> tuple[bytes, KdfParams]:
        data = self._request("GET", "/kdf-params", params={"email": email})
        return _unb64(data["salt_kdf"]), KdfParams.from_dict(data["kdf_params"])

    def login(self, email: str, auth_key: bytes) -> str:
        data = self._request(
            "POST", "/login", json={"email": email, "auth_key": _b64(auth_key)}
        )
        self.token = data["token"]
        return self.token

    def logout(self) -> None:
        self.token = None

    def get_vault(self) -> tuple[SealedVault, WrappedKey]:
        data = self._request("GET", "/vault", auth=True)
        sealed = SealedVault(
            version=int(data["version"]),
            nonce=_unb64(data["nonce"]),
            ciphertext=_unb64(data["ciphertext"]),
        )
        wrapped = WrappedKey(
            nonce=_unb64(data["wrapped_vk"]["nonce"]),
            ciphertext=_unb64(data["wrapped_vk"]["ciphertext"]),
        )
        return sealed, wrapped

    def put_vault(self, sealed: SealedVault) -> int:
        data = self._request(
            "PUT",
            "/vault",
            auth=True,
            json={
                "version": sealed.version,
                "nonce": _b64(sealed.nonce),
                "ciphertext": _b64(sealed.ciphertext),
            },
        )
        return int(data["version"])
