"""Registro, parámetros de KDF y login con AuthKey."""

from __future__ import annotations

import base64
import hashlib
import hmac

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db
from .models import User, VaultBlob
from .schemas import (
    KdfParamsIn,
    KdfParamsOut,
    LoginIn,
    RegisterIn,
    TokenOut,
    decode_b64,
    normalize_email,
)
from .security import client_ip, issue_token

router = APIRouter(tags=["auth"])

VK_WRAPPED_SIZE = 32 + 16  # VK + tag Poly1305
NONCE_SIZE = 24


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _bad_request(msg: str) -> HTTPException:
    return HTTPException(422, msg)


@router.post("/register", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)) -> TokenOut:
    settings = request.app.state.settings
    try:
        salt_kdf = decode_b64(body.salt_kdf, exact=16)
        auth_key = decode_b64(body.auth_key, exact=32)
        wvk_nonce = decode_b64(body.wrapped_vk.nonce, exact=NONCE_SIZE)
        wvk = decode_b64(body.wrapped_vk.ciphertext, exact=VK_WRAPPED_SIZE)
        v_nonce = decode_b64(body.vault.nonce, exact=NONCE_SIZE)
        v_ct = decode_b64(body.vault.ciphertext, max_len=settings.max_blob_bytes)
    except ValueError as exc:
        raise _bad_request(str(exc))
    if body.vault.version != 1:
        raise _bad_request("La bóveda inicial debe ser la versión 1")
    p = body.kdf_params
    if p.memory_kib < settings.min_client_memory_kib or p.time_cost < settings.min_client_time_cost:
        raise _bad_request("Parámetros de Argon2id por debajo del mínimo")

    if db.scalar(select(User.id).where(User.email == body.email)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "La cuenta ya existe")

    user = User(
        email=body.email,
        salt_kdf=salt_kdf,
        kdf_memory_kib=p.memory_kib,
        kdf_time_cost=p.time_cost,
        kdf_parallelism=p.parallelism,
        # El servidor nunca guarda AuthKey: sólo Argon2id(AuthKey, salt_srv).
        auth_hash=request.app.state.hasher.hash(auth_key),
        wrapped_vk_nonce=wvk_nonce,
        wrapped_vk=wvk,
    )
    db.add(user)
    db.flush()
    db.add(VaultBlob(user_id=user.id, version=1, nonce=v_nonce, ciphertext=v_ct))
    token = issue_token(db, user, settings.token_ttl_seconds)
    db.commit()
    return TokenOut(token=token, expires_in=settings.token_ttl_seconds)


@router.get("/kdf-params", response_model=KdfParamsOut)
def kdf_params(email: str, request: Request, db: Session = Depends(get_db)) -> KdfParamsOut:
    """Parámetros públicos para derivar en un dispositivo nuevo.

    Para correos inexistentes devuelve un salt falso pero determinista
    (HMAC(llave_servidor, email)), así la respuesta no revela si la cuenta existe.
    """
    settings = request.app.state.settings
    try:
        email = normalize_email(email)
    except ValueError as exc:
        raise _bad_request(str(exc))
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        fake = hmac.new(settings.fake_salt_key, email.encode(), hashlib.sha256).digest()[:16]
        return KdfParamsOut(
            salt_kdf=_b64(fake),
            kdf_params=KdfParamsIn(
                memory_kib=settings.min_client_memory_kib,
                time_cost=settings.min_client_time_cost,
                parallelism=4,
            ),
        )
    return KdfParamsOut(
        salt_kdf=_b64(user.salt_kdf),
        kdf_params=KdfParamsIn(
            memory_kib=user.kdf_memory_kib,
            time_cost=user.kdf_time_cost,
            parallelism=user.kdf_parallelism,
        ),
    )


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)) -> TokenOut:
    settings = request.app.state.settings
    limiter = request.app.state.rate_limiter
    ip = client_ip(request)
    limiter.check(ip, body.email)

    try:
        auth_key = decode_b64(body.auth_key, exact=32)
    except ValueError as exc:
        raise _bad_request(str(exc))

    user = db.scalar(select(User).where(User.email == body.email))
    # Se verifica siempre (contra un hash señuelo si no hay usuario) para no
    # filtrar por tiempo de respuesta si la cuenta existe.
    ok = request.app.state.hasher.verify(user.auth_hash if user else None, auth_key)
    if not ok or user is None:
        limiter.fail(ip, body.email)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Credenciales inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    limiter.success(ip, body.email)
    token = issue_token(db, user, settings.token_ttl_seconds)
    db.commit()
    return TokenOut(token=token, expires_in=settings.token_ttl_seconds)
