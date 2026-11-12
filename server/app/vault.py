"""Descarga y subida del blob cifrado con control optimista de versión."""

from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import update
from sqlalchemy.orm import Session

from .db import get_db
from .models import User, VaultBlob, utcnow
from .schemas import VaultIn, VaultOut, VersionOut, WrappedKeyIO, decode_b64
from .security import current_user

router = APIRouter(tags=["vault"])


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


@router.get("/vault", response_model=VaultOut)
def get_vault(user: User = Depends(current_user), db: Session = Depends(get_db)) -> VaultOut:
    blob = db.get(VaultBlob, user.id)
    if blob is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Bóveda no encontrada")
    return VaultOut(
        version=blob.version,
        nonce=_b64(blob.nonce),
        ciphertext=_b64(blob.ciphertext),
        wrapped_vk=WrappedKeyIO(
            nonce=_b64(user.wrapped_vk_nonce), ciphertext=_b64(user.wrapped_vk)
        ),
    )


@router.put("/vault", response_model=VersionOut)
def put_vault(
    body: VaultIn,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> VersionOut:
    """Acepta el blob sólo si `version == versión_actual + 1`.

    El UPDATE condicional (WHERE version = esperada) es atómico: si dos
    dispositivos suben a la vez, sólo uno gana y el otro recibe 409.
    El servidor no puede verificar el contenido (es opaco); la versión real
    está autenticada dentro del AAD y la verifica el cliente.
    """
    try:
        nonce = decode_b64(body.nonce, exact=24)
        ct = decode_b64(body.ciphertext, max_len=request.app.state.settings.max_blob_bytes)
    except ValueError as exc:
        raise HTTPException(422, str(exc))

    expected_current = body.version - 1
    result = db.execute(
        update(VaultBlob)
        .where(VaultBlob.user_id == user.id, VaultBlob.version == expected_current)
        .values(version=body.version, nonce=nonce, ciphertext=ct, updated_at=utcnow())
    )
    if result.rowcount != 1:
        db.rollback()
        current = db.get(VaultBlob, user.id)
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Versión desactualizada: el servidor está en v{current.version if current else '?'}",
        )
    db.commit()
    return VersionOut(version=body.version)
