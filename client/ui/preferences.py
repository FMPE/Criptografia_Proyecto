"""Preferencias locales del dispositivo: tiempos de bloqueo automático y del portapapeles.

Se guardan en `<PM_HOME>/preferences.json` (no son secretas y aplican a cualquier
cuenta del dispositivo). Los valores se acotan a un rango seguro: se pueden ajustar,
pero no desactivar el bloqueo ni dejar contraseñas en el portapapeles indefinidamente.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from client.vault.storage import _write_private, default_home

AUTO_LOCK_RANGE = (30, 60 * 60)  # 30 s .. 1 h
CLIPBOARD_RANGE = (5, 5 * 60)  # 5 s .. 5 min

AUTO_LOCK_CHOICES = [60, 120, 300, 600, 900, 1800, 3600]
CLIPBOARD_CHOICES = [10, 20, 30, 45, 60, 120]


def _clamp(value, lo: int, hi: int, default: int) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


@dataclass
class Preferences:
    auto_lock_seconds: int = 300
    clipboard_clear_seconds: int = 30

    def normalized(self) -> "Preferences":
        return Preferences(
            auto_lock_seconds=_clamp(self.auto_lock_seconds, *AUTO_LOCK_RANGE, 300),
            clipboard_clear_seconds=_clamp(self.clipboard_clear_seconds, *CLIPBOARD_RANGE, 30),
        )


def _path(home: Path | None) -> Path:
    return (home or default_home()) / "preferences.json"


def load_preferences(home: Path | None = None) -> Preferences:
    path = _path(home)
    try:
        doc = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return Preferences()
    if not isinstance(doc, dict):
        return Preferences()
    return Preferences(
        auto_lock_seconds=doc.get("auto_lock_seconds", 300),
        clipboard_clear_seconds=doc.get("clipboard_clear_seconds", 30),
    ).normalized()


def save_preferences(prefs: Preferences, home: Path | None = None) -> Preferences:
    prefs = prefs.normalized()
    path = _path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_private(path, json.dumps(asdict(prefs)).encode("utf-8"))
    return prefs


def describe_seconds(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds} s"
    minutes, rest = divmod(seconds, 60)
    return f"{minutes} min" if not rest else f"{minutes} min {rest} s"
