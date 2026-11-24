"""Passkeys Ed25519: registro de llaves públicas y login por challenge-response.

    POST   /passkeys             registra una pública (sesión + prueba de posesión)
    GET    /passkeys             lista las del usuario
    DELETE /passkeys/{id}        revoca una
    POST   /auth/challenge       emite challenge de 32 B, un solo uso, expira en 60 s
    POST   /auth/verify          verifica la firma y entrega un token de sesión

El servidor sólo conoce llaves públicas: un volcado de la BD no permite
autenticarse, y el servidor no puede suplantar al cliente ante sí mismo.
"""

from __future__ import annotations

import base64
import secrets
import struct
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .db import get_db
from .models import AuthChallenge, Passkey, User
from .schemas import (
    ChallengeIn,
    ChallengeOut,
    PasskeyIn,
    PasskeyOut,
    TokenOut,
    VerifyIn,
    decode_b64,
)
from .security import client_ip, current_user, issue_token

router = APIRouter(tags=["passkeys"])

AUTH_LABEL = b"pm-passkey-auth-v1"
REGISTER_LABEL = b"pm-passkey-register-v1"
PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64
CHALLENGE_SIZE = 32


# ---- Mensajes firmados (idénticos a client/crypto/passkeys.py) ------------- #
def _encode(*fields: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(f)) + f for f in fields)


def auth_message(email: str, challenge_id: str, challenge: bytes) -> bytes:
    return _encode(AUTH_LABEL, email.encode("utf-8"), challenge_id.encode("ascii"), challenge)


def registration_message(email: str, public_key: bytes) -> bytes:
    return _encode(REGISTER_LABEL, email.encode("utf-8"), public_key)


def _verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        VerifyKey(public_key).verify(message, signature)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


# ---- Utilidades -------------------------------------------------------------- #
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)  # SQLite pierde la zona


def _iso(dt: datetime | None) -> str | None:
    return _aware(dt).isoformat(timespec="seconds") if dt else None


def _out(pk: Passkey) -> PasskeyOut:
    return PasskeyOut(
        credential_id=pk.id,
        label=pk.label,
        public_key=_b64(pk.public_key),
        created_at=_iso(pk.created_at),
        last_used_at=_iso(pk.last_used_at),
    )


# ---- Gestión de llaves públicas ---------------------------------------------- #
@router.post("/passkeys", response_model=PasskeyOut, status_code=status.HTTP_201_CREATED)
def register_passkey(
    body: PasskeyIn,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> PasskeyOut:
    try:
        public_key = decode_b64(body.public_key, exact=PUBLIC_KEY_SIZE)
        proof = decode_b64(body.proof, exact=SIGNATURE_SIZE)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    # Prueba de posesión: evita registrar una pública ajena cuya privada no se tiene.
    if not _verify(public_key, registration_message(user.email, public_key), proof):
        raise HTTPException(422, "Prueba de posesión inválida")

    limit = request.app.state.settings.max_passkeys_per_user
    count = db.scalar(select(func.count()).select_from(Passkey).where(Passkey.user_id == user.id))
    if count >= limit:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Máximo {limit} passkeys por cuenta")
    if db.scalar(select(Passkey.id).where(Passkey.public_key == public_key)) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Esa llave pública ya está registrada")

    pk = Passkey(user_id=user.id, public_key=public_key, label=body.label.strip())
    db.add(pk)
    db.commit()
    return _out(pk)


@router.get("/passkeys", response_model=list[PasskeyOut])
def list_passkeys(
    user: User = Depends(current_user), db: Session = Depends(get_db)
) -> list[PasskeyOut]:
    rows = db.scalars(select(Passkey).where(Passkey.user_id == user.id).order_by(Passkey.id))
    return [_out(pk) for pk in rows]


@router.delete("/passkeys/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_passkey(
    credential_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> Response:
    result = db.execute(
        delete(Passkey).where(Passkey.id == credential_id, Passkey.user_id == user.id)
    )
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Passkey no encontrada")
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---- Challenge-response ------------------------------------------------------ #
@router.post("/auth/challenge", response_model=ChallengeOut)
def issue_challenge(
    body: ChallengeIn, request: Request, db: Session = Depends(get_db)
) -> ChallengeOut:
    settings = request.app.state.settings
    request.app.state.rate_limiter.check(client_ip(request), body.email)

    db.execute(delete(AuthChallenge).where(AuthChallenge.expires_at <= _now()))
    challenge_id = secrets.token_hex(16)
    challenge = secrets.token_bytes(CHALLENGE_SIZE)

    user = db.scalar(select(User).where(User.email == body.email))
    if user is not None:
        db.add(
            AuthChallenge(
                id=challenge_id,
                user_id=user.id,
                challenge=challenge,
                expires_at=_now() + timedelta(seconds=settings.challenge_ttl_seconds),
            )
        )
    # Si el correo no existe se responde igual (challenge no almacenado): no se
    # revela qué cuentas existen; /auth/verify simplemente fallará.
    db.commit()
    return ChallengeOut(
        challenge_id=challenge_id,
        challenge=_b64(challenge),
        expires_in=settings.challenge_ttl_seconds,
    )


@router.post("/auth/verify", response_model=TokenOut)
def verify_challenge(body: VerifyIn, request: Request, db: Session = Depends(get_db)) -> TokenOut:
    settings = request.app.state.settings
    limiter = request.app.state.rate_limiter
    ip = client_ip(request)
    limiter.check(ip, body.email)

    def reject() -> HTTPException:
        limiter.fail(ip, body.email)
        return HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Autenticación con passkey inválida",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        signature = decode_b64(body.signature, exact=SIGNATURE_SIZE)
    except ValueError:
        raise reject()

    user = db.scalar(select(User).where(User.email == body.email))
    row = db.get(AuthChallenge, body.challenge_id)
    if user is None or row is None:
        raise reject()

    # Se consume ANTES de verificar la firma: un solo uso aunque la firma falle.
    # El DELETE es atómico: con dos verificaciones simultáneas sólo una obtiene rowcount 1.
    consumed = db.execute(
        delete(AuthChallenge).where(AuthChallenge.id == body.challenge_id)
    ).rowcount == 1
    db.commit()
    if not consumed or row.user_id != user.id or _aware(row.expires_at) <= _now():
        raise reject()

    pk = db.get(Passkey, body.credential_id)
    if pk is None or pk.user_id != user.id:
        raise reject()
    message = auth_message(user.email, body.challenge_id, row.challenge)
    if not _verify(pk.public_key, message, signature):
        raise reject()

    limiter.success(ip, body.email)
    pk.last_used_at = _now()
    token = issue_token(db, user, settings.token_ttl_seconds)
    db.commit()
    return TokenOut(token=token, expires_in=settings.token_ttl_seconds)
