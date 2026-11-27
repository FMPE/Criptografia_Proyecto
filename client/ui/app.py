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
from .preferences import load_preferences
from .vault_view import VaultView

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_pins() -> list[str]:
    """Pines SPKI: PM_PINS (separados por coma) o server/certs/pin.txt.

    En un despliegue real el pin viaja con el cliente (no se lee del directorio del
    servidor); leer pin.txt es una comodidad para el entorno de desarrollo.
    """
    env = os.environ.get("PM_PINS")
    if env:
        return [p.strip() for p in env.split(",") if p.strip()]
    pin_file = Path(os.environ.get("PM_PIN_FILE", str(REPO_ROOT / "server" / "certs" / "pin.txt")))
    if pin_file.exists():
        lines = pin_file.read_text("utf-8").splitlines()
        return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
    raise SystemExit(
        "No hay pin del servidor configurado. Ejecuta "
        "'python -m server.scripts.gen_cert --pin-only' o define PM_PINS=sha256//…"
    )


def build_manager() -> VaultManager:
    url = os.environ.get("PM_SERVER_URL", "https://127.0.0.1:8443")
    ca = os.environ.get("PM_CA_CERT", str(REPO_ROOT / "server" / "certs" / "cert.pem"))
    if not Path(ca).exists():
        raise SystemExit(f"No se encontró el certificado del servidor: {ca}")
    try:
        api = ApiClient(url, ca_cert=ca, pins=load_pins())
    except ValueError as exc:
        raise SystemExit(f"Configuración de pines inválida: {exc}")
    return VaultManager(api)


def make_main(manager: VaultManager):
    async def main(page: ft.Page) -> None:
        page.title = "Gestor de contraseñas"
        page.theme_mode = ft.ThemeMode.SYSTEM
        page.theme = ft.Theme(color_scheme_seed=ft.Colors.INDIGO)
        page.dark_theme = ft.Theme(color_scheme_seed=ft.Colors.INDIGO)
        page.padding = 0
        page.window.width, page.window.height = 1120, 720
        page.window.min_width, page.window.min_height = 860, 560

        ui = Ui(page, load_preferences(manager.home))
        state: dict = {"vault": None}

        def show(control: ft.Control) -> None:
            page.controls.clear()
            # Toda la ventana reporta actividad (mouse y rueda) al temporizador de
            # bloqueo; hover/scroll no compiten con los gestos de los controles hijos.
            page.add(
                ft.GestureDetector(
                    content=control, expand=True, hover_interval=1000,
                    on_hover=ui.touch, on_enter=ui.touch, on_scroll=ui.touch,
                )
            )
            page.update()

        def show_login() -> None:
            ui.idle.stop()
            state["vault"] = None
            show(LoginView(ui, manager, on_unlocked=show_vault).control)

        def show_vault(secret_key: str | None) -> None:
            view = VaultView(ui, manager, on_locked=show_login)
            state["vault"] = view
            show(view.control)
            ui.idle.start()
            if secret_key:
                show_emergency_kit(ui, manager.email, secret_key)

        async def on_idle() -> None:
            """Bloqueo automático: se olvidan las llaves aunque haya cambios sin subir."""
            if state["vault"] is None or not manager.is_unlocked:
                return
            lost = state["vault"].dirty
            ui.close_dialogs()
            await ui.clipboard_guard.clear_if_ours()
            manager.lock()
            show_login()
            ui.notify(
                "Bóveda bloqueada por inactividad"
                + (" (se descartaron cambios sin subir)" if lost else ""),
                error=lost,
            )

        ui.idle.on_idle = on_idle
        page.on_keyboard_event = ui.touch

        # Cerrar la ventana bloquea la bóveda; avisa si hay cambios sin subir.
        async def on_window_event(e) -> None:
            if e.type != ft.WindowEventType.CLOSE:
                return
            view = state["vault"]
            if view is not None and view.dirty and not await confirm(
                ui, "Salir", "Hay cambios sin subir que se perderán. ¿Salir igual?", "Salir", destructive=True
            ):
                return
            ui.idle.stop()
            await ui.clipboard_guard.clear_if_ours()
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
