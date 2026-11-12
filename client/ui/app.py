"""Punto de entrada de la aplicación de escritorio.

    python -m client.ui.app

Variables de entorno:
    PM_SERVER_URL  (por defecto https://127.0.0.1:8443)
    PM_CA_CERT     certificado en el que se confía (por defecto server/certs/cert.pem)
    PM_HOME        directorio de datos locales (por defecto ~/.pwmanager)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from client.net.api_client import ApiClient
from client.vault.manager import VaultManager

from .dialogs import EmergencyKitDialog, LoginDialog
from .main_window import MainWindow

REPO_ROOT = Path(__file__).resolve().parents[2]


def build_manager() -> VaultManager:
    url = os.environ.get("PM_SERVER_URL", "https://127.0.0.1:8443")
    ca = os.environ.get("PM_CA_CERT", str(REPO_ROOT / "server" / "certs" / "cert.pem"))
    if not Path(ca).exists():
        raise SystemExit(f"No se encontró el certificado del servidor: {ca}")
    return VaultManager(ApiClient(url, ca_cert=ca))


def main() -> int:
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    manager = build_manager()
    state: dict = {}

    def show_login() -> None:
        dlg = LoginDialog(manager)
        if not dlg.exec():
            app.quit()
            return
        if dlg.new_secret_key:
            EmergencyKitDialog(manager.email, dlg.new_secret_key).exec()
            dlg.new_secret_key = None
        win = MainWindow(manager)
        win.locked.connect(show_login)
        state["win"] = win  # mantener referencia viva
        win.show()

    show_login()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
