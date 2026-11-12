from __future__ import annotations

import pytest

from client.crypto import aead, kdf, keys
from client.crypto.kdf import DEFAULT_PARAMS, KdfParams, WeakKdfParamsError

from .conftest import FAST_PARAMS

SK = bytes(range(32))
SALT = bytes(16)
PW = "correct horse battery staple"


# --------------------------------------------------------------------------- KDF
def test_hkdf_extract_rfc5869_vector():
    # RFC 5869, Test Case 1 (HKDF-Extract con SHA-256)
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    prk = kdf.hkdf_extract(salt, ikm)
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    okm = kdf.hkdf_expand(prk, bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


def test_derivation_is_deterministic_and_domain_separated():
    a = kdf.derive_keys(PW, SK, SALT, FAST_PARAMS)
    b = kdf.derive_keys(PW, SK, SALT, FAST_PARAMS)
    assert a == b
    assert len(a.auth_key) == len(a.kek) == 32
    assert a.auth_key != a.kek


@pytest.mark.parametrize(
    "pw, sk, salt",
    [
        (PW + "!", SK, SALT),
        (PW, bytes(32), SALT),  # otra Secret Key
        (PW, SK, b"\x01" * 16),  # otro salt_kdf
    ],
)
def test_any_input_change_changes_both_keys(pw, sk, salt):
    base = kdf.derive_keys(PW, SK, SALT, FAST_PARAMS)
    other = kdf.derive_keys(pw, sk, salt, FAST_PARAMS)
    assert other.auth_key != base.auth_key
    assert other.kek != base.kek


def test_password_is_nfkc_normalized():
    composed = "contraseña-maestra"
    decomposed = "contraseña-maestra"
    assert kdf.derive_keys(composed, SK, SALT, FAST_PARAMS) == kdf.derive_keys(
        decomposed, SK, SALT, FAST_PARAMS
    )


def test_default_params_match_design():
    assert DEFAULT_PARAMS == KdfParams(memory_kib=65536, time_cost=3, parallelism=4)


def test_real_params_derive():
    # Una derivación con los parámetros reales del diseño (64 MiB, t=3, p=4).
    keys_ = kdf.derive_keys(PW, SK, SALT, DEFAULT_PARAMS)
    assert len(keys_.kek) == 32


def test_weak_params_from_server_are_rejected():
    with pytest.raises(WeakKdfParamsError):
        kdf.check_params(KdfParams(memory_kib=8, time_cost=1, parallelism=1), DEFAULT_PARAMS)


def test_input_validation():
    with pytest.raises(ValueError):
        kdf.derive_keys(PW, b"short", SALT, FAST_PARAMS)
    with pytest.raises(ValueError):
        kdf.derive_keys("", SK, SALT, FAST_PARAMS)


# -------------------------------------------------------------------------- AEAD
KEY = bytes(range(32))


def test_aead_roundtrip_and_fresh_nonces():
    n1, c1 = aead.encrypt(KEY, b"hola", b"aad")
    n2, c2 = aead.encrypt(KEY, b"hola", b"aad")
    assert len(n1) == 24
    assert n1 != n2 and c1 != c2
    assert aead.decrypt(KEY, n1, c1, b"aad") == b"hola"


def test_aead_detects_tampering():
    nonce, ct = aead.encrypt(KEY, b"secreto", b"aad")
    for i in range(len(ct)):
        bad = bytearray(ct)
        bad[i] ^= 0x01
        with pytest.raises(aead.DecryptionError):
            aead.decrypt(KEY, nonce, bytes(bad), b"aad")


def test_aead_rejects_wrong_aad_key_or_nonce():
    nonce, ct = aead.encrypt(KEY, b"secreto", b"aad")
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(KEY, nonce, ct, b"otro")
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(bytes(32), nonce, ct, b"aad")
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(KEY, bytes(24), ct, b"aad")


def test_encode_aad_is_unambiguous():
    assert aead.encode_aad(b"ab", b"c") != aead.encode_aad(b"a", b"bc")


# ------------------------------------------------------------------------- Llaves
def test_wrap_unwrap_vault_key():
    kek = bytes(range(32, 64))
    vk = keys.generate_vault_key()
    wrapped = keys.wrap_vault_key(kek, vk, "a@b.c")
    assert vk not in wrapped.ciphertext
    assert keys.unwrap_vault_key(kek, wrapped, "a@b.c") == vk


def test_unwrap_fails_with_wrong_kek_or_user():
    kek = bytes(range(32, 64))
    wrapped = keys.wrap_vault_key(kek, keys.generate_vault_key(), "a@b.c")
    with pytest.raises(aead.DecryptionError):
        keys.unwrap_vault_key(bytes(32), wrapped, "a@b.c")
    with pytest.raises(aead.DecryptionError):
        keys.unwrap_vault_key(kek, wrapped, "mallory@b.c")


def test_secret_key_format_roundtrip():
    sk = keys.generate_secret_key()
    text = keys.format_secret_key(sk)
    assert text.startswith("PM1-")
    assert keys.parse_secret_key(text) == sk
    assert keys.parse_secret_key(text.lower().replace("-", " ")) == sk


def test_secret_key_typo_is_detected():
    text = keys.format_secret_key(keys.generate_secret_key())
    i = 6  # un carácter dentro del primer bloque
    typo = text[:i] + ("A" if text[i] != "A" else "B") + text[i + 1 :]
    with pytest.raises(keys.InvalidSecretKeyError):
        keys.parse_secret_key(typo)
