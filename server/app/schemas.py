"""Esquemas de la API. Los binarios viajan en Base64 estándar."""

from __future__ import annotations

import base64
import re
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}$")


def decode_b64(value: str, *, exact: int | None = None, max_len: int | None = None) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError("Base64 inválido") from exc
    if exact is not None and len(raw) != exact:
        raise ValueError(f"Se esperaban {exact} bytes")
    if max_len is not None and len(raw) > max_len:
        raise ValueError("Dato demasiado grande")
    return raw


def normalize_email(v: str) -> str:
    v = v.strip().lower()
    if not _EMAIL_RE.match(v):
        raise ValueError("Correo inválido")
    return v


Email = Annotated[str, AfterValidator(normalize_email)]


class KdfParamsIn(BaseModel):
    memory_kib: int = Field(ge=8, le=4 * 1024 * 1024)
    time_cost: int = Field(ge=1, le=20)
    parallelism: int = Field(ge=1, le=16)


class WrappedKeyIO(BaseModel):
    nonce: str
    ciphertext: str


class VaultIn(BaseModel):
    version: int = Field(ge=1)
    nonce: str
    ciphertext: str


class RegisterIn(BaseModel):
    email: Email
    salt_kdf: str
    kdf_params: KdfParamsIn
    auth_key: str
    wrapped_vk: WrappedKeyIO
    vault: VaultIn


class LoginIn(BaseModel):
    email: Email
    auth_key: str


class TokenOut(BaseModel):
    token: str
    token_type: str = "bearer"
    expires_in: int


class KdfParamsOut(BaseModel):
    salt_kdf: str
    kdf_params: KdfParamsIn


class VaultOut(BaseModel):
    version: int
    nonce: str
    ciphertext: str
    wrapped_vk: WrappedKeyIO


class VersionOut(BaseModel):
    version: int


# ---- Passkeys --------------------------------------------------------------- #
class PasskeyIn(BaseModel):
    public_key: str
    label: str = Field(min_length=1, max_length=64)
    # Firma de enc("pm-passkey-register-v1", email, public_key): prueba de posesión.
    proof: str


class PasskeyOut(BaseModel):
    credential_id: int
    label: str
    public_key: str
    created_at: str
    last_used_at: str | None = None


class ChallengeIn(BaseModel):
    email: Email


class ChallengeOut(BaseModel):
    challenge_id: str
    challenge: str
    expires_in: int


class VerifyIn(BaseModel):
    email: Email
    challenge_id: str = Field(min_length=1, max_length=32)
    credential_id: int
    signature: str
