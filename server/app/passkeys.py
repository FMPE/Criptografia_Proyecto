"""Passkeys Ed25519 (challenge-response). Pendiente (P1).

Endpoints previstos:
  POST /passkeys        registra una llave pública Ed25519 (32 B) del usuario autenticado
  POST /auth/challenge  emite un nonce de 32 B, de un solo uso y con expiración
  POST /auth/verify     verifica Ed25519.verify(pk, challenge, sig) y entrega token
"""

from fastapi import APIRouter

router = APIRouter(tags=["passkeys"])
