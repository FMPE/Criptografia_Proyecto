"""Primitivas de seguridad del servidor: hash de AuthKey, tokens de sesión, rate limiting."""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .db import get_db
from .models import SessionToken, User


class AuthHasher:
    """Argon2id(AuthKey, salt_srv). El salt aleatorio va embebido en el hash PHC."""

    def __init__(self, settings: Settings) -> None:
        self._ph = PasswordHasher(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_kib,
            parallelism=settings.argon2_parallelism,
            hash_len=32,
            salt_len=16,
        )
        # Hash señuelo para igualar el tiempo de respuesta con correos inexistentes.
        self._dummy = self._ph.hash(secrets.token_bytes(32))

    def hash(self, auth_key: bytes) -> str:
        return self._ph.hash(auth_key)

    def verify(self, stored: str | None, auth_key: bytes) -> bool:
        try:
            return self._ph.verify(stored or self._dummy, auth_key) and stored is not None
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def issue_token(db: Session, user: User, ttl_seconds: int) -> str:
    token = secrets.token_urlsafe(32)  # 256 bits
    now = datetime.now(timezone.utc)
    db.add(
        SessionToken(
            token_hash=token_digest(token),
            user_id=user.id,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
    )
    return token


class LoginRateLimiter:
    """Ventana deslizante de fallos por (IP, correo). En memoria: suficiente para un nodo."""

    def __init__(self, max_failures: int, window_seconds: int) -> None:
        self.max_failures = max_failures
        self.window = window_seconds
        self._failures: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: tuple[str, str], now: float) -> deque[float]:
        q = self._failures[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def check(self, ip: str, email: str) -> None:
        with self._lock:
            q = self._prune((ip, email), time.monotonic())
            if len(q) >= self.max_failures:
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "Demasiados intentos fallidos; espera unos minutos",
                )

    def fail(self, ip: str, email: str) -> None:
        with self._lock:
            self._failures[(ip, email)].append(time.monotonic())

    def success(self, ip: str, email: str) -> None:
        with self._lock:
            self._failures.pop((ip, email), None)


_bearer = HTTPBearer(auto_error=False)


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Sesión inválida o expirada",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if creds is None or creds.scheme.lower() != "bearer":
        raise unauthorized
    row = db.scalar(
        select(SessionToken).where(SessionToken.token_hash == token_digest(creds.credentials))
    )
    if row is None:
        raise unauthorized
    expires = row.expires_at
    if expires.tzinfo is None:  # SQLite no conserva la zona horaria
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc):
        db.delete(row)
        db.commit()
        raise unauthorized
    user = db.get(User, row.user_id)
    if user is None:
        raise unauthorized
    return user


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"
