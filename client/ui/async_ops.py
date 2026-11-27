"""Contexto compartido de la UI: operaciones bloqueantes, avisos y portapapeles.

Argon2id (64 MiB) y las llamadas HTTPS bloquean entre 0,2 s y varios segundos.
Flet atiende la interfaz en un bucle asyncio, así que esas llamadas se ejecutan en
un hilo aparte (`asyncio.to_thread`) mientras una capa semitransparente con un
indicador de progreso tapa la ventana. Esa capa también impide que el usuario
dispare otra operación sobre `VaultManager` mientras la anterior sigue en curso.
"""

from __future__ import annotations

import asyncio
import functools
from typing import Any, Callable, TypeVar

import flet as ft

from .clipboard import ClipboardGuard
from .idle import InactivityMonitor
from .preferences import Preferences

T = TypeVar("T")


class Ui:
    def __init__(self, page: ft.Page, prefs: Preferences | None = None) -> None:
        self.page = page
        self.prefs = prefs or Preferences()
        self.clipboard = ft.Clipboard()
        self.file_picker = ft.FilePicker()
        self.clipboard_guard = ClipboardGuard(
            self.clipboard.get, self.clipboard.set, self.prefs.clipboard_clear_seconds
        )
        # `on_idle` lo asigna app.py (sabe cómo bloquear y volver al login).
        self.idle = InactivityMonitor(self.prefs.auto_lock_seconds, self._noop)
        self._busy_text = ft.Text("", size=15)
        self._busy = ft.Container(
            content=ft.Column(
                [ft.ProgressRing(), self._busy_text],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                alignment=ft.MainAxisAlignment.CENTER,
                tight=True,
                spacing=16,
            ),
            bgcolor=ft.Colors.with_opacity(0.55, ft.Colors.BLACK),
            alignment=ft.Alignment.CENTER,
            expand=True,
            visible=False,
        )
        page.overlay.append(self._busy)

    @staticmethod
    async def _noop() -> None:
        return None

    def touch(self, *_args) -> None:
        """Actividad del usuario: reinicia el temporizador de bloqueo automático."""
        self.idle.touch()

    def apply_preferences(self, prefs: Preferences) -> None:
        self.prefs = prefs
        self.idle.set_timeout(prefs.auto_lock_seconds)
        self.clipboard_guard.clear_after = prefs.clipboard_clear_seconds

    def close_dialogs(self) -> None:
        """Cierra todos los diálogos abiertos (p. ej. al bloquear por inactividad)."""
        for _ in range(20):
            if self.page.pop_dialog() is None:
                break

    async def run(self, fn: Callable[..., T], *args: Any, message: str = "Procesando…", **kwargs: Any) -> T:
        """Ejecuta `fn` en un hilo mostrando la capa de espera. Propaga sus excepciones.

        Mientras corre no cuenta como inactividad (Argon2id puede tardar segundos).
        """
        self._busy_text.value = message
        self._busy.visible = True
        self.page.update()
        try:
            with self.idle.busy():
                return await asyncio.to_thread(functools.partial(fn, *args, **kwargs))
        finally:
            self._busy.visible = False
            self.page.update()

    def notify(self, message: str, error: bool = False) -> None:
        self.page.show_dialog(
            ft.SnackBar(
                content=ft.Text(message, color=ft.Colors.ON_ERROR if error else None),
                bgcolor=ft.Colors.ERROR if error else None,
                duration=4000 if error else 2500,
            )
        )
