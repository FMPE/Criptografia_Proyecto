"""Modelo de la bóveda en claro (sólo vive en RAM del cliente)."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone

VAULT_FORMAT = 1


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Entry:
    service: str
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def matches(self, query: str) -> bool:
        q = query.strip().lower()
        if not q:
            return True
        haystack = (self.service, self.username, self.url, self.notes, *self.tags)
        return any(q in h.lower() for h in haystack)

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in allowed})


class Vault:
    def __init__(self, entries: list[Entry] | None = None) -> None:
        self._entries: dict[str, Entry] = {e.id: e for e in (entries or [])}

    # ---- CRUD ------------------------------------------------------------- #
    def add(self, entry: Entry) -> Entry:
        if not entry.service.strip():
            raise ValueError("El servicio es obligatorio")
        if entry.id in self._entries:
            raise ValueError("Ya existe una entrada con ese id")
        self._entries[entry.id] = entry
        return entry

    def get(self, entry_id: str) -> Entry:
        try:
            return self._entries[entry_id]
        except KeyError:
            raise KeyError(f"No existe la entrada {entry_id}") from None

    def update(self, entry_id: str, **changes) -> Entry:
        current = self.get(entry_id)
        changes.pop("id", None)
        changes.pop("created_at", None)
        updated = replace(current, **changes, updated_at=_now())
        if not updated.service.strip():
            raise ValueError("El servicio es obligatorio")
        self._entries[entry_id] = updated
        return updated

    def delete(self, entry_id: str) -> None:
        self.get(entry_id)
        del self._entries[entry_id]

    def duplicate(self, entry_id: str) -> Entry:
        src = self.get(entry_id)
        copy = Entry(
            service=f"{src.service} (copia)",
            username=src.username,
            password=src.password,
            url=src.url,
            notes=src.notes,
            tags=list(src.tags),
        )
        return self.add(copy)

    # ---- Consulta --------------------------------------------------------- #
    def all(self) -> list[Entry]:
        return sorted(self._entries.values(), key=lambda e: e.service.lower())

    def search(self, query: str = "", tag: str | None = None) -> list[Entry]:
        return [
            e for e in self.all() if e.matches(query) and (tag is None or tag in e.tags)
        ]

    def tags(self) -> list[str]:
        return sorted({t for e in self._entries.values() for t in e.tags})

    def __len__(self) -> int:
        return len(self._entries)

    # ---- Serialización ---------------------------------------------------- #
    def to_bytes(self) -> bytes:
        doc = {"format": VAULT_FORMAT, "entries": [asdict(e) for e in self.all()]}
        return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Vault":
        doc = json.loads(data.decode("utf-8"))
        if doc.get("format") != VAULT_FORMAT:
            raise ValueError("Formato de bóveda no soportado")
        return cls([Entry.from_dict(e) for e in doc["entries"]])
