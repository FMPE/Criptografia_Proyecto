"""Certificate pinning por llave pública (SPKI), además de la validación TLS normal.

    pin = "sha256//" + Base64(SHA-256(SubjectPublicKeyInfo DER))

Es el mismo formato que HPKP y `curl --pinnedpubkey`. Se fija la llave pública y no
el certificado completo, así el certificado se puede renovar sin cambiar el pin si
se conserva la llave. Se aceptan varios pines (llave actual + llave de respaldo).

La validación normal (cadena, nombre, vigencia, TLS 1.3) sigue ocurriendo: el pin es
una comprobación ADICIONAL. Protege contra un MITM que presente un certificado
válido emitido por una CA comprometida o por una CA instalada en el equipo
(proxies corporativos, antivirus que inspeccionan TLS, malware).
"""

from __future__ import annotations

import base64
import hashlib
import ssl
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import serialization

PIN_PREFIX = "sha256//"


class PinMismatchError(ssl.SSLCertVerificationError):
    """El servidor presentó una llave pública que no está entre los pines."""


def spki_pin(cert: bytes | x509.Certificate) -> str:
    """Pin `sha256//…` de la llave pública de un certificado (DER o objeto x509)."""
    if isinstance(cert, (bytes, bytearray)):
        cert = x509.load_der_x509_certificate(bytes(cert))
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return PIN_PREFIX + base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def normalize_pins(pins: Iterable[str]) -> frozenset[str]:
    result = set()
    for raw in pins:
        pin = raw.strip()
        if not pin:
            continue
        if not pin.startswith(PIN_PREFIX):
            raise ValueError(f"Pin inválido (debe empezar con '{PIN_PREFIX}'): {pin!r}")
        try:
            digest = base64.b64decode(pin[len(PIN_PREFIX):], validate=True)
        except ValueError as exc:
            raise ValueError(f"Pin inválido (Base64 mal formado): {pin!r}") from exc
        if len(digest) != hashlib.sha256().digest_size:
            raise ValueError(f"Pin inválido (no es un SHA-256): {pin!r}")
        result.add(pin)
    if not result:
        raise ValueError("Se necesita al menos un pin")
    return frozenset(result)


class PinnedSSLContext(ssl.SSLContext):
    """SSLContext que, tras el handshake, exige que la llave del servidor esté fijada.

    httpcore (cliente síncrono de httpx) abre el socket TCP y llama a `wrap_socket`.
    El handshake ocurre dentro de esa llamada; la comprobación se hace justo después,
    ANTES de que se envíe cualquier byte de la petición HTTP.
    """

    pins: frozenset[str]

    def wrap_socket(self, sock, *args, **kwargs):  # type: ignore[override]
        ssock = super().wrap_socket(sock, *args, **kwargs)
        if not kwargs.get("do_handshake_on_connect", True):
            ssock.do_handshake()
        der = ssock.getpeercert(binary_form=True)
        presented = spki_pin(der) if der else "(sin certificado)"
        if presented not in self.pins:
            ssock.close()
            raise PinMismatchError(
                "La llave pública del servidor no coincide con el pin configurado "
                f"(recibido {presented}). Posible ataque MITM."
            )
        return ssock

    def wrap_bio(self, *args, **kwargs):  # type: ignore[override]
        # Lo usan los clientes asíncronos y TLS-in-TLS (proxies); aquí no se verificaría el pin.
        raise NotImplementedError("El pinning sólo está implementado para el cliente síncrono")


def pinned_context(pins: Iterable[str], ca_cert: str | None = None) -> PinnedSSLContext:
    """Contexto TLS 1.3 con validación completa (CA + nombre) y además pinning de SPKI."""
    ctx = PinnedSSLContext(ssl.PROTOCOL_TLS_CLIENT)  # check_hostname=True, CERT_REQUIRED
    ctx.pins = normalize_pins(pins)
    if ca_cert:
        ctx.load_verify_locations(cafile=ca_cert)
    else:
        ctx.load_default_certs()
    return ctx
