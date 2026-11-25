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

T = TypeVar("T")


class Ui:
    def __init__(self, page: ft.Page) -> None:
        self.page = page
        self.clipboard = ft.Clipboard()
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

    async def run(self, fn: Callable[..., T], *args: Any, message: str = "Procesando…", **kwargs: Any) -> T:
        """Ejecuta `fn` en un hilo mostrando la capa de espera. Propaga sus excepciones."""
        self._busy_text.value = message
        self._busy.visible = True
        self.page.update()
        try:
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
