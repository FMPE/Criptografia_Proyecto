"""Certificate pinning con servidores TLS 1.3 reales (en hilos, sin red externa).

Escenario de ataque: una CA en la que el cliente confía queda comprometida (o es
una CA de inspección TLS instalada en el equipo) y emite un certificado VÁLIDO
para 127.0.0.1 con la llave del atacante. La validación TLS normal lo acepta; el
pin de la llave pública legítima no.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import ipaddress
import socket
import ssl
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from client.net.api_client import ApiClient, CertificatePinningError, make_tls_context
from client.net.pinning import normalize_pins, spki_pin
from client.vault.manager import VaultManager
from server.app.config import Settings
from server.app.main import create_app, make_server_config

from .conftest import FAST_PARAMS

EMAIL = "franco@utec.edu.pe"
PW = "Tr3s-Tristes-Tigres!"
WRONG_PIN = "sha256//" + base64.b64encode(b"\x00" * 32).decode()


# --------------------------------------------------------------------------- #
# PKI de prueba
# --------------------------------------------------------------------------- #
def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _pem_key(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("PM Test CA"))
        .issuer_name(_name("PM Test CA"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(ca_key, ca_cert):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("127.0.0.1"))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


# --------------------------------------------------------------------------- #
# Servidores
# --------------------------------------------------------------------------- #
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class RunningServer:
    def __init__(self, certfile: Path, keyfile: Path) -> None:
        self.app = create_app(
            Settings(
                database_url="sqlite:///:memory:",
                argon2_memory_kib=1024, argon2_time_cost=1, argon2_parallelism=1,
                min_client_memory_kib=FAST_PARAMS.memory_kib,
                min_client_time_cost=FAST_PARAMS.time_cost,
                fake_salt_key=b"k" * 32,
            )
        )
        self.app.state.hits = 0

        @self.app.middleware("http")
        async def count_requests(request, call_next):
            self.app.state.hits += 1
            return await call_next(request)

        self.port = _free_port()
        self.url = f"https://127.0.0.1:{self.port}"
        config = make_server_config(
            self.app, str(certfile), str(keyfile), "127.0.0.1", self.port, log_level="warning"
        )
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 15
        while not self.server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("El servidor de prueba no arrancó")
            time.sleep(0.05)

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    ca_key, ca_cert = make_ca()
    (d / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    out = {"ca": str(d / "ca.pem")}
    for who in ("legit", "attacker"):
        key, cert = make_leaf(ca_key, ca_cert)
        (d / f"{who}.key").write_bytes(_pem_key(key))
        (d / f"{who}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        out[who] = (d / f"{who}.pem", d / f"{who}.key", cert, key)
    return out


@pytest.fixture(scope="module")
def servers(pki):
    legit = RunningServer(*pki["legit"][:2])
    attacker = RunningServer(*pki["attacker"][:2])
    yield {"legit": legit, "attacker": attacker}
    legit.stop()
    attacker.stop()


@pytest.fixture
def legit_pin(pki) -> str:
    return spki_pin(pki["legit"][2])


# --------------------------------------------------------------------------- #
# Pruebas
# --------------------------------------------------------------------------- #
def test_correct_pin_connects(servers, pki, legit_pin):
    api = ApiClient(servers["legit"].url, ca_cert=pki["ca"], pins=[legit_pin])
    salt, params = api.get_kdf_params("x@utec.edu.pe")
    assert len(salt) == 16


def test_mitm_with_valid_certificate_from_trusted_ca_is_rejected(servers, pki, legit_pin):
    attacker = servers["attacker"]
    hits_before = attacker.app.state.hits
    api = ApiClient(attacker.url, ca_cert=pki["ca"], pins=[legit_pin])
    with pytest.raises(CertificatePinningError, match="MITM"):
        api.get_kdf_params("x@utec.edu.pe")
    # La conexión se corta tras el handshake: el atacante no recibe ninguna petición HTTP.
    assert attacker.app.state.hits == hits_before


def test_without_pinning_the_same_mitm_succeeds(servers, pki):
    """Lo que agrega el pinning: sin pin, la CA comprometida basta para el MITM."""
    attacker = servers["attacker"]
    hits_before = attacker.app.state.hits
    ApiClient(attacker.url, ca_cert=pki["ca"]).get_kdf_params("x@utec.edu.pe")
    assert attacker.app.state.hits == hits_before + 1


def test_backup_pin_allows_rotation(servers, pki, legit_pin):
    ApiClient(servers["legit"].url, ca_cert=pki["ca"], pins=[WRONG_PIN, legit_pin]).get_kdf_params("x@utec.edu.pe")
    with pytest.raises(CertificatePinningError):
        ApiClient(servers["legit"].url, ca_cert=pki["ca"], pins=[WRONG_PIN]).get_kdf_params("x@utec.edu.pe")


def test_pin_failure_does_not_fall_back_to_offline_mode(servers, pki, legit_pin, tmp_path):
    home = tmp_path / "laptop"
    m = VaultManager(ApiClient(servers["legit"].url, ca_cert=pki["ca"], pins=[legit_pin]),
                     home=home, kdf_params=FAST_PARAMS)
    m.register(EMAIL, PW)
    m.lock()

    # Servidor caído: NetworkError → se abre la caché local en modo sin conexión.
    offline = VaultManager(ApiClient(f"https://127.0.0.1:{_free_port()}", ca_cert=pki["ca"], pins=[legit_pin]),
                           home=home, kdf_params=FAST_PARAMS)
    offline.unlock(EMAIL, PW)
    assert offline.is_unlocked and not offline.online

    # MITM detectado: NO se trata como "sin conexión"; el usuario debe enterarse.
    mitm = VaultManager(ApiClient(servers["attacker"].url, ca_cert=pki["ca"], pins=[legit_pin]),
                        home=home, kdf_params=FAST_PARAMS)
    with pytest.raises(CertificatePinningError):
        mitm.unlock(EMAIL, PW)
    assert not mitm.is_unlocked


def test_pinned_context_still_requires_tls13_and_hostname(pki, legit_pin):
    ctx = make_tls_context(pki["ca"], [legit_pin])
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_3
    assert ctx.check_hostname and ctx.verify_mode == ssl.CERT_REQUIRED


def test_spki_pin_matches_independent_computation(pki):
    cert = pki["legit"][2]
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    expected = "sha256//" + base64.b64encode(hashlib.sha256(spki).digest()).decode()
    assert spki_pin(cert) == expected
    assert spki_pin(cert.public_bytes(serialization.Encoding.DER)) == expected


def test_pin_survives_certificate_renewal_with_same_key(pki):
    """Se fija la llave, no el certificado: renovar con la misma llave no rompe el pin."""
    cert, key = pki["legit"][2], pki["legit"][3]
    renewed = (
        x509.CertificateBuilder()
        .subject_name(cert.subject).issuer_name(cert.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(cert.not_valid_before_utc).not_valid_after(cert.not_valid_after_utc)
        .sign(key, hashes.SHA256())
    )
    assert renewed.fingerprint(hashes.SHA256()) != cert.fingerprint(hashes.SHA256())
    assert spki_pin(renewed) == spki_pin(cert)


@pytest.mark.parametrize(
    "bad",
    [["abc"], ["sha1//" + base64.b64encode(b"\x00" * 20).decode()],
     ["sha256//no-es-base64!"], ["sha256//" + base64.b64encode(b"\x00" * 20).decode()], []],
)
def test_malformed_pins_are_rejected(bad):
    with pytest.raises(ValueError):
        normalize_pins(bad)
    if bad:
        with pytest.raises(ValueError):
            ApiClient("https://127.0.0.1:1", pins=bad)
