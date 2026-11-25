"""Genera un certificado TLS autofirmado (ECDSA P-256) para desarrollo.

    python -m server.scripts.gen_cert              # genera cert.pem, key.pem y pin.txt
    python -m server.scripts.gen_cert --pin-only   # sólo calcula el pin del cert.pem actual

El cliente confía explícitamente en cert.pem (PM_CA_CERT) y además exige que la
llave pública coincida con el pin de pin.txt (o PM_PINS):
    pin = "sha256//" + Base64(SHA-256(SubjectPublicKeyInfo DER))
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

CERT_DIR = Path(__file__).resolve().parents[1] / "certs"


def spki_pin(cert: x509.Certificate) -> str:
    # Mismo cálculo que client/net/pinning.py (el servidor no importa código del cliente).
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return "sha256//" + base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii")


def write_pin(cert: x509.Certificate) -> None:
    pin = spki_pin(cert)
    header = "# Pin SPKI del servidor (no es secreto). Distribúyelo con el cliente."
    (CERT_DIR / "pin.txt").write_text(f"{header}\n{pin}\n", "utf-8")
    print(f"Pin SPKI:    {pin}")
    print(f"Guardado en: {CERT_DIR / 'pin.txt'}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pin-only", action="store_true",
                        help="calcula el pin del cert.pem existente sin regenerarlo")
    args = parser.parse_args()
    if args.pin_only:
        cert_path = CERT_DIR / "cert.pem"
        if not cert_path.exists():
            raise SystemExit(f"No existe {cert_path}; ejecuta gen_cert sin --pin-only")
        write_pin(x509.load_pem_x509_certificate(cert_path.read_bytes()))
        return

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=False,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    key_path = CERT_DIR / "key.pem"
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    (CERT_DIR / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    fp = cert.fingerprint(hashes.SHA256()).hex(":")
    print(f"Certificado: {CERT_DIR / 'cert.pem'}")
    print(f"SHA-256:     {fp}")
    write_pin(cert)


if __name__ == "__main__":
    main()
