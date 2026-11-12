"""Aplicación FastAPI y arranque con TLS 1.3.

Uso:
    python -m server.scripts.gen_cert          # una vez: certificado autofirmado
    python -m server.app.main                  # https://127.0.0.1:8443
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import Response

from . import auth, passkeys, vault
from .config import Settings
from .db import make_sessionmaker
from .security import AuthHasher, LoginRateLimiter

CERT_DIR = Path(__file__).resolve().parents[1] / "certs"

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    app = FastAPI(
        title="Password Manager Sync",
        # Sin documentación interactiva expuesta en producción.
        docs_url=None if os.environ.get("PM_ENV") == "production" else "/docs",
        redoc_url=None,
        openapi_url=None if os.environ.get("PM_ENV") == "production" else "/openapi.json",
    )
    app.state.settings = settings
    app.state.SessionLocal = make_sessionmaker(settings.database_url)
    app.state.hasher = AuthHasher(settings)
    app.state.rate_limiter = LoginRateLimiter(
        settings.login_max_failures, settings.login_window_seconds
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next) -> Response:
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response

    app.include_router(auth.router)
    app.include_router(vault.router)
    app.include_router(passkeys.router)
    return app


def run() -> None:
    import uvicorn

    certfile = os.environ.get("PM_TLS_CERT", str(CERT_DIR / "cert.pem"))
    keyfile = os.environ.get("PM_TLS_KEY", str(CERT_DIR / "key.pem"))
    if not (Path(certfile).exists() and Path(keyfile).exists()):
        raise SystemExit(
            "No hay certificado TLS. Ejecuta primero: python -m server.scripts.gen_cert"
        )

    config = uvicorn.Config(
        create_app(),
        host=os.environ.get("PM_HOST", "127.0.0.1"),
        port=int(os.environ.get("PM_PORT", "8443")),
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
        server_header=False,
        proxy_headers=False,
    )
    config.load()
    # Se exige TLS 1.3: sin downgrade a TLS 1.2 o anteriores.
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3
    uvicorn.Server(config).run()


if __name__ == "__main__":
    run()
