"""Punto de entrada de la aplicación de escritorio (Flet).

    python -m client.ui.app

Variables de entorno:
    PM_SERVER_URL  (por defecto https://127.0.0.1:8443)
    PM_CA_CERT     certificado en el que se confía (por defecto server/certs/cert.pem)
    PM_HOME        directorio de datos locales (por defecto ~/.pwmanager)
"""

from __future__ import annotations

import os
from pathlib import Path

import flet as ft

from client.net.api_client import ApiClient
from client.vault.manager import VaultManager

from .async_ops import Ui
from .dialogs import confirm, show_emergency_kit
from .login_view import LoginView
from .vault_view import VaultView

REPO_ROOT = Path(__file__).resolve().parents[2]


def build_manager() -> VaultManager:
    url = os.environ.get("PM_SERVER_URL", "https://127.0.0.1:8443")
    ca = os.environ.get("PM_CA_CERT", str(REPO_ROOT / "server" / "certs" / "cert.pem"))
    if not Path(ca).exists():
        raise SystemExit(f"No se encontró el certificado del servidor: {ca}")
    return VaultManager(ApiClient(url, ca_cert=ca))


def make_main(manager: VaultManager):
    async def main(page: ft.Page) -> None:
        page.title = "Gestor de contraseñas"
        page.theme_mode = ft.ThemeMode.SYSTEM
        page.theme = ft.Theme(color_scheme_seed=ft.Colors.INDIGO)
        page.dark_theme = ft.Theme(color_scheme_seed=ft.Colors.INDIGO)
        page.padding = 0
        page.window.width, page.window.height = 1120, 720
        page.window.min_width, page.window.min_height = 860, 560

        ui = Ui(page)
        state: dict = {"vault": None}

        def show(control: ft.Control) -> None:
            page.controls.clear()
            page.add(control)
            page.update()

        def show_login() -> None:
            state["vault"] = None
            show(LoginView(ui, manager, on_unlocked=show_vault).control)

        def show_vault(secret_key: str | None) -> None:
            view = VaultView(ui, manager, on_locked=show_login)
            state["vault"] = view
            show(view.control)
            if secret_key:
                show_emergency_kit(ui, manager.email, secret_key)

        # Cerrar la ventana bloquea la bóveda; avisa si hay cambios sin subir.
        async def on_window_event(e) -> None:
            if e.type != ft.WindowEventType.CLOSE:
                return
            view = state["vault"]
            if view is not None and view.dirty and not await confirm(
                ui, "Salir", "Hay cambios sin subir que se perderán. ¿Salir igual?", "Salir", destructive=True
            ):
                return
            manager.lock()
            await page.window.destroy()

        page.window.prevent_close = True
        page.window.on_event = on_window_event
        show_login()

    return main


def main() -> None:
    manager = build_manager()  # falla rápido si falta el certificado
    # La primera ejecución descarga el cliente de escritorio de Flet desde GitHub con
    # urllib. El Python de Anaconda no trae CAs actualizadas, así que se usa el bundle
    # de certifi. No afecta a ApiClient: su contexto TLS sólo confía en PM_CA_CERT.
    try:
        import certifi

        os.environ.setdefault("SSL_CERT_FILE", certifi.where())
    except ImportError:  # pragma: no cover - certifi llega como dependencia de httpx
        pass
    ft.run(make_main(manager))


if __name__ == "__main__":
    main()
