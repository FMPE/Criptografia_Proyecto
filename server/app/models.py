"""Modelo de datos del servidor. Nada aquí permite descifrar la bóveda."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)

    # Parámetros públicos de la KDF del cliente (necesarios en un dispositivo nuevo).
    salt_kdf: Mapped[bytes] = mapped_column(LargeBinary(16))
    kdf_memory_kib: Mapped[int] = mapped_column(Integer)
    kdf_time_cost: Mapped[int] = mapped_column(Integer)
    kdf_parallelism: Mapped[int] = mapped_column(Integer)

    # Argon2id(AuthKey, salt_srv) en formato PHC ($argon2id$v=19$m=...$salt$hash).
    auth_hash: Mapped[str] = mapped_column(String(255))

    # VK envuelta con KEK: opaca para el servidor.
    wrapped_vk_nonce: Mapped[bytes] = mapped_column(LargeBinary(24))
    wrapped_vk: Mapped[bytes] = mapped_column(LargeBinary(64))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    vault: Mapped["VaultBlob"] = relationship(back_populates="user", uselist=False)


class VaultBlob(Base):
    __tablename__ = "vaults"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)
    version: Mapped[int] = mapped_column(Integer)
    nonce: Mapped[bytes] = mapped_column(LargeBinary(24))
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped[User] = relationship(back_populates="vault")


class SessionToken(Base):
    __tablename__ = "sessions"

    # Se guarda SHA-256(token): un volcado de la BD no entrega sesiones válidas.
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
