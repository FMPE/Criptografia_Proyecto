"""Generador de contraseñas con el CSPRNG del sistema operativo (módulo `secrets`)."""

from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!#$%&*+-=?@^_~.,:;()[]{}"
AMBIGUOUS = set("Il1O0o|`'\"")

MIN_LENGTH = 8
MAX_LENGTH = 128


@dataclass(frozen=True)
class GeneratorOptions:
    length: int = 20
    lower: bool = True
    upper: bool = True
    digits: bool = True
    symbols: bool = True
    avoid_ambiguous: bool = False

    def pools(self) -> list[str]:
        selected = [
            pool
            for pool, enabled in (
                (LOWER, self.lower),
                (UPPER, self.upper),
                (DIGITS, self.digits),
                (SYMBOLS, self.symbols),
            )
            if enabled
        ]
        if self.avoid_ambiguous:
            selected = ["".join(c for c in p if c not in AMBIGUOUS) for p in selected]
        return [p for p in selected if p]


def generate_password(opts: GeneratorOptions = GeneratorOptions()) -> str:
    pools = opts.pools()
    if not pools:
        raise ValueError("Selecciona al menos un tipo de carácter")
    if not MIN_LENGTH <= opts.length <= MAX_LENGTH:
        raise ValueError(f"La longitud debe estar entre {MIN_LENGTH} y {MAX_LENGTH}")
    if opts.length < len(pools):
        raise ValueError("Longitud insuficiente para incluir todas las clases")

    alphabet = "".join(pools)
    # Un carácter de cada clase seleccionada garantiza que la política se cumple...
    chars = [secrets.choice(pool) for pool in pools]
    # ...y el resto sale uniformemente del alfabeto completo.
    chars += [secrets.choice(alphabet) for _ in range(opts.length - len(pools))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def estimate_generator_entropy(opts: GeneratorOptions) -> float:
    """Entropía (bits) de una contraseña generada: L · log2(|alfabeto|).

    Es una cota superior ligeramente optimista porque forzar una de cada clase
    restringe un poco el espacio; la diferencia es < 1 bit para L ≥ 12.
    """
    alphabet = "".join(opts.pools())
    if not alphabet:
        return 0.0
    return opts.length * math.log2(len(alphabet))


def estimate_password_entropy(password: str) -> float:
    """Estimación ingenua para contraseñas escritas por humanos (medidor de la maestra).

    Usa el tamaño del conjunto de caracteres observado; sobreestima contraseñas
    con palabras de diccionario. Sirve como piso mínimo, no como garantía.
    """
    if not password:
        return 0.0
    size = 0
    if any(c in LOWER for c in password):
        size += len(LOWER)
    if any(c in UPPER for c in password):
        size += len(UPPER)
    if any(c in DIGITS for c in password):
        size += len(DIGITS)
    if any(not c.isalnum() for c in password):
        size += 33
    if any(ord(c) > 127 for c in password):
        size += 100
    # Penaliza repetición: cuenta sólo caracteres distintos más la mitad de repetidos.
    distinct = len(set(password))
    effective_len = distinct + (len(password) - distinct) / 2
    return effective_len * math.log2(max(size, 2))
