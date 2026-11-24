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


@dataclass
class Passkey:
    """Par Ed25519 guardado dentro de la bóveda: la privada sólo existe cifrada bajo VK."""

    credential_id: int  # id que asignó el servidor al registrar la pública
    label: str
    private_key: str  # seed Ed25519 en Base64
    public_key: str  # Base64
    created_at: str = field(default_factory=_now)

    @classmethod
    def from_dict(cls, d: dict) -> "Passkey":
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in allowed})


class Vault:
    def __init__(
        self, entries: list[Entry] | None = None, passkeys: list[Passkey] | None = None
    ) -> None:
        self._entries: dict[str, Entry] = {e.id: e for e in (entries or [])}
        self._passkeys: dict[int, Passkey] = {p.credential_id: p for p in (passkeys or [])}

    # ---- Passkeys (no son entradas: no aparecen en búsquedas) ------------- #
    def add_passkey(self, pk: Passkey) -> Passkey:
        if pk.credential_id in self._passkeys:
            raise ValueError("Ya existe una passkey con ese id")
        self._passkeys[pk.credential_id] = pk
        return pk

    def remove_passkey(self, credential_id: int) -> None:
        if self._passkeys.pop(credential_id, None) is None:
            raise KeyError(f"No existe la passkey {credential_id}")

    def passkeys(self) -> list[Passkey]:
        return sorted(self._passkeys.values(), key=lambda p: p.created_at)

    def latest_passkey(self) -> Passkey | None:
        pks = self.passkeys()
        return pks[-1] if pks else None

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
        doc = {
            "format": VAULT_FORMAT,
            "entries": [asdict(e) for e in self.all()],
            "passkeys": [asdict(p) for p in self.passkeys()],
        }
        return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Vault":
        doc = json.loads(data.decode("utf-8"))
        if doc.get("format") != VAULT_FORMAT:
            raise ValueError("Formato de bóveda no soportado")
        return cls(
            [Entry.from_dict(e) for e in doc["entries"]],
            # Opcional: las bóvedas creadas antes de las passkeys no tienen esta clave.
            [Passkey.from_dict(p) for p in doc.get("passkeys", [])],
        )
