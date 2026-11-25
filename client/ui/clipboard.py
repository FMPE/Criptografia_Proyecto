"""Único punto por el que la aplicación copia datos al portapapeles.

TODO (P1, Persona B): limpiar el portapapeles tras N segundos, sólo si todavía
contiene lo que copió la aplicación (`await ui.clipboard.get()` lo permite).
"""

from __future__ import annotations

from .async_ops import Ui


async def copy_to_clipboard(ui: Ui, text: str, what: str = "Texto") -> None:
    if not text:
        return
    await ui.clipboard.set(text)
    ui.notify(f"{what} copiado al portapapeles")
