"""Diálogos de la cuenta: cambio de contraseña maestra, preferencias y respaldo cifrado."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Callable

import flet as ft

from client.crypto.generator import estimate_password_entropy
from client.net.api_client import ApiError, NetworkError
from client.vault.export import EXPORT_EXTENSION, ExportError
from client.vault.manager import (
    MIN_MASTER_ENTROPY_BITS,
    MIN_MASTER_LENGTH,
    VaultError,
    VaultManager,
    check_master_password,
)

from .async_ops import Ui
from .dialogs import strength
from .preferences import (
    AUTO_LOCK_CHOICES,
    CLIPBOARD_CHOICES,
    Preferences,
    describe_seconds,
    save_preferences,
)

_ERRORS = (VaultError, ApiError, NetworkError, ExportError, ValueError, OSError)


def _password_field(label: str, **kwargs) -> ft.TextField:
    return ft.TextField(
        label=label, password=True, can_reveal_password=True, prefix_icon=ft.Icons.PASSWORD, **kwargs
    )


class _StrengthMeter:
    def __init__(self) -> None:
        self.bar = ft.ProgressBar(value=0, bar_height=6, border_radius=ft.BorderRadius.all(3))
        self.text = ft.Text("", size=12)
        self.update_for("")

    def update_for(self, pw: str) -> None:
        bits = estimate_password_entropy(pw)
        self.bar.value, self.bar.color, label = strength(bits)
        hint = ""
        if len(pw) < MIN_MASTER_LENGTH:
            hint = f" · mínimo {MIN_MASTER_LENGTH} caracteres"
        elif bits < MIN_MASTER_ENTROPY_BITS:
            hint = f" · mínimo {MIN_MASTER_ENTROPY_BITS:.0f} bits"
        self.text.value = f"{label} · {bits:.0f} bits estimados{hint}"


class _FormDialog:
    """Base: título, campos, mensaje de error y botones Cancelar / acción."""

    def __init__(self, ui: Ui, title: str, icon, fields: list[ft.Control], ok_label: str, width: int = 480):
        self.ui = ui
        self.message = ft.Text("", color=ft.Colors.ERROR, size=13)
        self.ok = ft.FilledButton(ok_label, on_click=self._on_ok)
        self.dialog = ft.AlertDialog(
            modal=True,
            title=ft.Row([ft.Icon(icon), ft.Text(title)]),
            content=ft.Column(
                [*fields, self.message], tight=True, spacing=12, width=width,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
            ),
            actions=[ft.TextButton("Cancelar", on_click=lambda _e: ui.page.pop_dialog()), self.ok],
        )

    def fail(self, text: str) -> None:
        self.message.value = f"⚠ {text}"
        self.dialog.update()

    async def _on_ok(self, _e) -> None:  # pragma: no cover - lo implementa cada diálogo
        raise NotImplementedError

    def show(self) -> None:
        self.ui.page.show_dialog(self.dialog)


# --------------------------------------------------------------------------- #
# Cambio de contraseña maestra
# --------------------------------------------------------------------------- #
class ChangePasswordDialog(_FormDialog):
    def __init__(self, ui: Ui, manager: VaultManager, on_done: Callable[[], None]) -> None:
        self.manager = manager
        self.on_done = on_done
        self.old = _password_field("Contraseña actual", autofocus=True)
        self.new = _password_field("Contraseña nueva", on_change=self._meter)
        self.confirm = _password_field("Confirmar contraseña nueva", on_submit=self._on_ok)
        self.meter = _StrengthMeter()
        info = ft.Text(
            "Sólo se re-envuelve la llave de la bóveda (VK) con la llave derivada de la "
            "contraseña nueva; la bóveda no se vuelve a cifrar. La Secret Key no cambia. "
            "Se cerrarán las sesiones abiertas en tus otros dispositivos.",
            size=13, color=ft.Colors.ON_SURFACE_VARIANT,
        )
        super().__init__(
            ui, "Cambiar contraseña maestra", ft.Icons.PASSWORD,
            [info, self.old, self.new, self.meter.bar, self.meter.text, self.confirm],
            "Cambiar",
        )

    def _meter(self, _e) -> None:
        self.meter.update_for(self.new.value or "")
        self.dialog.update()

    def _clear(self) -> None:
        self.old.value = self.new.value = self.confirm.value = ""

    async def _on_ok(self, _e) -> None:
        old, new = self.old.value or "", self.new.value or ""
        if not old or not new:
            return self.fail("Completa todos los campos")
        if new != (self.confirm.value or ""):
            return self.fail("Las contraseñas nuevas no coinciden")
        try:
            await self.ui.run(
                self.manager.change_password, old, new,
                message="Derivando llaves nuevas y re-envolviendo la VK…",
            )
        except _ERRORS as exc:
            self.old.value = ""
            return self.fail(str(exc))
        self._clear()
        self.ui.page.pop_dialog()
        self.on_done()
        self.ui.notify("Contraseña maestra cambiada. Las demás sesiones se cerraron.")


# --------------------------------------------------------------------------- #
# Preferencias
# --------------------------------------------------------------------------- #
class PreferencesDialog(_FormDialog):
    def __init__(self, ui: Ui, home: Path | None) -> None:
        self.home = home
        p = ui.prefs
        self.auto_lock = ft.Dropdown(
            label="Bloquear tras inactividad",
            value=str(p.auto_lock_seconds),
            options=[ft.DropdownOption(key=str(s), text=describe_seconds(s)) for s in _with(AUTO_LOCK_CHOICES, p.auto_lock_seconds)],
        )
        self.clipboard = ft.Dropdown(
            label="Borrar el portapapeles tras",
            value=str(p.clipboard_clear_seconds),
            options=[ft.DropdownOption(key=str(s), text=describe_seconds(s)) for s in _with(CLIPBOARD_CHOICES, p.clipboard_clear_seconds)],
        )
        note = ft.Text(
            "El portapapeles sólo se borra si todavía contiene lo que copió la aplicación. "
            "Estas preferencias son de este dispositivo.",
            size=12, color=ft.Colors.ON_SURFACE_VARIANT,
        )
        super().__init__(ui, "Preferencias de seguridad", ft.Icons.TIMER_OUTLINED,
                         [self.auto_lock, self.clipboard, note], "Guardar")

    async def _on_ok(self, _e) -> None:
        try:
            prefs = save_preferences(
                Preferences(int(self.auto_lock.value), int(self.clipboard.value)), self.home
            )
        except (OSError, TypeError, ValueError) as exc:
            return self.fail(str(exc))
        self.ui.apply_preferences(prefs)
        self.ui.page.pop_dialog()
        self.ui.notify(
            f"Bloqueo tras {describe_seconds(prefs.auto_lock_seconds)} · "
            f"portapapeles {describe_seconds(prefs.clipboard_clear_seconds)}"
        )


def _with(choices: list[int], current: int) -> list[int]:
    return sorted(set(choices) | {current})


# --------------------------------------------------------------------------- #
# Respaldo cifrado
# --------------------------------------------------------------------------- #
class ExportDialog(_FormDialog):
    def __init__(self, ui: Ui, manager: VaultManager) -> None:
        self.manager = manager
        self.pw = _password_field("Contraseña del respaldo", autofocus=True, on_change=self._meter)
        self.confirm = _password_field("Confirmar contraseña", on_submit=self._on_ok)
        self.meter = _StrengthMeter()
        info = ft.Text(
            "El archivo .pmx se cifra con XChaCha20-Poly1305 usando una llave derivada con "
            "Argon2id de esta contraseña (salt y nonce nuevos). Usa una distinta de la "
            "maestra y guárdala aparte: sin ella el respaldo no se puede abrir. "
            "Las passkeys no se exportan.",
            size=13, color=ft.Colors.ON_SURFACE_VARIANT,
        )
        super().__init__(ui, "Exportar respaldo cifrado", ft.Icons.FILE_UPLOAD_OUTLINED,
                         [info, self.pw, self.meter.bar, self.meter.text, self.confirm], "Elegir archivo…")

    def _meter(self, _e) -> None:
        self.meter.update_for(self.pw.value or "")
        self.dialog.update()

    async def _on_ok(self, _e) -> None:
        pw = self.pw.value or ""
        if pw != (self.confirm.value or ""):
            return self.fail("Las contraseñas no coinciden")
        try:
            check_master_password(pw, "La contraseña de respaldo")
        except VaultError as exc:
            return self.fail(str(exc))
        path = await self.ui.file_picker.save_file(
            dialog_title="Guardar respaldo cifrado",
            file_name=f"boveda-{date.today().isoformat()}.{EXPORT_EXTENSION}",
            allowed_extensions=[EXPORT_EXTENSION],
        )
        self.ui.touch()
        if not path:
            return
        if not path.lower().endswith(f".{EXPORT_EXTENSION}"):
            path += f".{EXPORT_EXTENSION}"
        try:
            n = await self.ui.run(self.manager.export_backup, Path(path), pw,
                                  message="Derivando llave del respaldo y cifrando…")
        except _ERRORS as exc:
            return self.fail(str(exc))
        self.pw.value = self.confirm.value = ""
        self.ui.page.pop_dialog()
        self.ui.notify(f"Respaldo cifrado con {n} entradas guardado en {Path(path).name}")


class ImportDialog(_FormDialog):
    def __init__(self, ui: Ui, manager: VaultManager, path: Path, on_done: Callable[[int], None]) -> None:
        self.manager = manager
        self.path = path
        self.on_done = on_done
        self.pw = _password_field("Contraseña del respaldo", autofocus=True, on_submit=self._on_ok)
        info = ft.Text(
            f"Archivo: {path.name}\nLas entradas se agregan a tu bóveda; no se sobrescribe "
            "ninguna existente. Si el archivo fue alterado, la importación se rechaza.",
            size=13, color=ft.Colors.ON_SURFACE_VARIANT,
        )
        super().__init__(ui, "Importar respaldo cifrado", ft.Icons.FILE_DOWNLOAD_OUTLINED,
                         [info, self.pw], "Importar")

    async def _on_ok(self, _e) -> None:
        try:
            n = await self.ui.run(self.manager.import_backup, self.path, self.pw.value or "",
                                  message="Verificando y descifrando el respaldo…")
        except _ERRORS as exc:
            self.pw.value = ""
            return self.fail(str(exc))
        self.pw.value = ""
        self.ui.page.pop_dialog()
        self.on_done(n)
        self.ui.notify(f"Se importaron {n} entradas" if n else "No había entradas nuevas que importar")


async def pick_and_import(ui: Ui, manager: VaultManager, on_done: Callable[[int], None]) -> None:
    """`on_done(n)` recibe cuántas entradas se agregaron (0: no se subió nada)."""
    if not manager.online:
        ui.notify("Sin conexión: la bóveda es de sólo lectura", error=True)
        return
    files = await ui.file_picker.pick_files(
        dialog_title="Elegir respaldo cifrado", allowed_extensions=[EXPORT_EXTENSION]
    )
    ui.touch()
    if not files or not files[0].path:
        return
    ImportDialog(ui, manager, Path(files[0].path), on_done).show()
