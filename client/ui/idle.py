"""Bloqueo automático por inactividad.

`InactivityMonitor` no depende de Flet: la UI llama a `touch()` con cada evento del
usuario (teclado, mouse, clics, operaciones) y una tarea asyncio revisa cada pocos
segundos si pasó el tiempo configurado sin actividad. Si pasó, llama a `on_idle`
una sola vez y se detiene hasta el próximo `start()`.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import Awaitable, Callable, Iterator


class InactivityMonitor:
    def __init__(
        self,
        timeout_seconds: float,
        on_idle: Callable[[], Awaitable[None]],
        clock: Callable[[], float] = time.monotonic,
        poll_seconds: float = 1.0,
    ) -> None:
        self.timeout = float(timeout_seconds)
        self.on_idle = on_idle
        self._clock = clock
        self._poll = poll_seconds
        self._last = clock()
        self._task: asyncio.Task | None = None
        self._busy = 0

    # ---- Actividad ---------------------------------------------------- #
    def touch(self, *_args) -> None:
        """Registra actividad del usuario. Acepta (y descarta) el evento de Flet."""
        self._last = self._clock()

    @contextlib.contextmanager
    def busy(self) -> Iterator[None]:
        """Mientras dure una operación larga (Argon2id, red) no se bloquea."""
        self._busy += 1
        self.touch()
        try:
            yield
        finally:
            self._busy -= 1
            self.touch()

    def set_timeout(self, seconds: float) -> None:
        self.timeout = float(seconds)
        self.touch()

    def remaining(self) -> float:
        return max(0.0, self.timeout - (self._clock() - self._last))

    def is_idle(self) -> bool:
        return self._busy == 0 and self._clock() - self._last >= self.timeout

    # ---- Ciclo -------------------------------------------------------- #
    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        self.stop()
        self.touch()
        self._task = asyncio.get_running_loop().create_task(self._run())

    def stop(self) -> None:
        if self._task is not None and not self._task.done() and self._task is not _current():
            self._task.cancel()
        self._task = None

    async def check(self) -> bool:
        """Una iteración: si está inactivo, llama a `on_idle`. Devuelve si lo llamó."""
        if not self.is_idle():
            return False
        await self.on_idle()
        return True

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self._poll)
            if await self.check():
                return


def _current() -> asyncio.Task | None:
    try:
        return asyncio.current_task()
    except RuntimeError:
        return None
