"""Bloqueo por inactividad, limpieza del portapapeles y preferencias (sin Flet)."""

from __future__ import annotations

import asyncio

from client.ui.clipboard import ClipboardGuard
from client.ui.idle import InactivityMonitor
from client.ui.preferences import Preferences, load_preferences, save_preferences


class FakeClipboard:
    def __init__(self) -> None:
        self.value: str | None = None
        self.writes: list[str] = []

    async def get(self) -> str | None:
        return self.value

    async def set(self, text: str) -> None:
        self.value = text
        self.writes.append(text)


def run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------- #
# Portapapeles
# --------------------------------------------------------------------------- #
def test_clipboard_cleared_after_delay():
    async def scenario():
        cb = FakeClipboard()
        guard = ClipboardGuard(cb.get, cb.set, clear_after_seconds=0.05)
        await guard.copy("hunter2")
        assert cb.value == "hunter2"
        await asyncio.sleep(0.15)
        return cb

    cb = run(scenario())
    assert cb.value == ""


def test_clipboard_not_touched_if_user_copied_something_else():
    async def scenario():
        cb = FakeClipboard()
        guard = ClipboardGuard(cb.get, cb.set, clear_after_seconds=0.05)
        await guard.copy("hunter2")
        cb.value = "texto del usuario"  # otra app copió algo
        await asyncio.sleep(0.15)
        return cb

    cb = run(scenario())
    assert cb.value == "texto del usuario"
    assert cb.writes == ["hunter2"]  # nunca se escribió ""


def test_new_copy_restarts_timer_and_only_last_one_is_cleared():
    async def scenario():
        cb = FakeClipboard()
        guard = ClipboardGuard(cb.get, cb.set, clear_after_seconds=0.1)
        await guard.copy("primera")
        await asyncio.sleep(0.06)
        await guard.copy("segunda")
        await asyncio.sleep(0.06)  # el timer de "primera" ya habría vencido
        mid = cb.value
        await asyncio.sleep(0.1)
        return mid, cb.value

    mid, end = run(scenario())
    assert mid == "segunda" and end == ""


def test_clear_on_lock_is_immediate_and_guard_keeps_only_a_hash():
    async def scenario():
        cb = FakeClipboard()
        guard = ClipboardGuard(cb.get, cb.set, clear_after_seconds=60)
        await guard.copy("hunter2")
        assert guard.pending
        assert "hunter2" not in repr(vars(guard))
        cleared = await guard.clear_if_ours()
        return cleared, cb.value, guard.pending

    assert run(scenario()) == (True, "", False)


def test_unreadable_clipboard_is_left_alone():
    async def scenario():
        cb = FakeClipboard()

        async def broken_read():
            raise RuntimeError("no hay texto")

        guard = ClipboardGuard(broken_read, cb.set, clear_after_seconds=60)
        await guard.copy("hunter2")
        return await guard.clear_if_ours(), cb.value

    assert run(scenario()) == (False, "hunter2")


# --------------------------------------------------------------------------- #
# Inactividad
# --------------------------------------------------------------------------- #
class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_monitor_fires_only_after_timeout_without_activity():
    clock = FakeClock()
    fired = []

    async def on_idle():
        fired.append(clock.t)

    m = InactivityMonitor(300, on_idle, clock=clock)

    async def scenario():
        clock.t += 299
        assert not await m.check()
        m.touch()  # actividad: reinicia el contador
        clock.t += 299
        assert not await m.check()
        clock.t += 1
        assert await m.check()

    run(scenario())
    assert len(fired) == 1


def test_monitor_does_not_fire_while_busy():
    clock = FakeClock()
    m = InactivityMonitor(10, lambda: asyncio.sleep(0), clock=clock)
    with m.busy():
        clock.t += 100
        assert not m.is_idle()
    assert not m.is_idle()  # salir de busy cuenta como actividad
    clock.t += 10
    assert m.is_idle()


def test_monitor_task_locks_once_and_can_be_stopped():
    async def scenario():
        fired = []

        async def on_idle():
            fired.append(1)

        m = InactivityMonitor(0.05, on_idle, poll_seconds=0.01)
        m.start()
        await asyncio.sleep(0.2)
        assert fired == [1] and not m.running  # se detiene tras bloquear

        m.start()
        m.stop()
        await asyncio.sleep(0.1)
        return fired

    assert run(scenario()) == [1]


def test_set_timeout_applies_new_value():
    clock = FakeClock()
    m = InactivityMonitor(300, lambda: asyncio.sleep(0), clock=clock)
    m.set_timeout(60)
    clock.t += 60
    assert m.is_idle()


# --------------------------------------------------------------------------- #
# Preferencias
# --------------------------------------------------------------------------- #
def test_preferences_roundtrip_and_defaults(tmp_path):
    assert load_preferences(tmp_path) == Preferences()
    save_preferences(Preferences(auto_lock_seconds=120, clipboard_clear_seconds=10), tmp_path)
    assert load_preferences(tmp_path) == Preferences(120, 10)


def test_preferences_are_clamped(tmp_path):
    saved = save_preferences(Preferences(auto_lock_seconds=1, clipboard_clear_seconds=10**6), tmp_path)
    assert saved == Preferences(30, 300)
    (tmp_path / "preferences.json").write_text('{"auto_lock_seconds": "x"}')
    assert load_preferences(tmp_path) == Preferences(300, 30)
    (tmp_path / "preferences.json").write_text("no es json")
    assert load_preferences(tmp_path) == Preferences()
