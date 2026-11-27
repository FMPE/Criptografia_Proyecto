"""Único punto por el que la aplicación copia datos al portapapeles.

Cada copia programa una limpieza a los N segundos (configurable). Al vencer, se lee
el portapapeles y sólo se borra si TODAVÍA contiene lo que copió la aplicación: si el
usuario copió otra cosa mientras tanto, no se toca. Para comparar no se guarda el texto
copiado sino su SHA-256, así el secreto no queda retenido en memoria por el temporizador.

Al bloquear la bóveda (manual, por inactividad o al cerrar) se limpia de inmediato.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from typing import TYPE_CHECKING, Awaitable, Callable

if TYPE_CHECKING:  # evita el import circular con async_ops
    from .async_ops import Ui


def _digest(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8")).digest()


class ClipboardGuard:
    def __init__(
        self,
        read: Callable[[], Awaitable[str | None]],
        write: Callable[[str], Awaitable[None]],
        clear_after_seconds: float = 30,
    ) -> None:
        self._read = read
        self._write = write
        self.clear_after = float(clear_after_seconds)
        self._digest: bytes | None = None
        self._task: asyncio.Task | None = None

    @property
    def pending(self) -> bool:
        return self._digest is not None

    async def copy(self, text: str) -> None:
        self._cancel_timer()
        await self._write(text)
        self._digest = _digest(text)
        self._task = asyncio.get_running_loop().create_task(self._clear_later(self.clear_after))

    async def clear_if_ours(self) -> bool:
        """Borra el portapapeles si aún contiene lo último que copió la app."""
        self._cancel_timer()
        digest, self._digest = self._digest, None
        if digest is None:
            return False
        try:
            current = await self._read()
        except Exception:  # nosec B110 - sin texto legible (imagen, error del SO): no se toca
            return False
        if current is None or not hmac.compare_digest(_digest(current), digest):
            return False
        await self._write("")
        return True

    async def _clear_later(self, delay: float) -> None:
        await asyncio.sleep(delay)
        self._task = None  # que clear_if_ours no se cancele a sí misma
        await self.clear_if_ours()

    def _cancel_timer(self) -> None:
        task, self._task = self._task, None
        if task is not None and not task.done() and task is not asyncio.current_task():
            task.cancel()


async def copy_to_clipboard(ui: "Ui", text: str, what: str = "Texto") -> None:
    if not text:
        return
    guard = ui.clipboard_guard
    ui.touch()
    try:
        await guard.copy(text)
    except Exception:  # el SO/navegador puede negar el acceso (PlatformException)
        ui.notify("No se pudo copiar al portapapeles", error=True)
        return
    ui.notify(f"{what} copiado · se borrará del portapapeles en {guard.clear_after:.0f} s")
