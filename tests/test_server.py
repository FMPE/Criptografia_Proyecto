"""Pruebas de la API a nivel HTTP (sin pasar por el cliente)."""

from __future__ import annotations

import base64

from sqlalchemy import select

from server.app.models import SessionToken, User


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


AUTH_KEY = b"A" * 32


def register_body(email="ana@utec.edu.pe", auth_key=AUTH_KEY, version=1):
    return {
        "email": email,
        "salt_kdf": b64(b"s" * 16),
        "kdf_params": {"memory_kib": 1024, "time_cost": 1, "parallelism": 1},
        "auth_key": b64(auth_key),
        "wrapped_vk": {"nonce": b64(b"n" * 24), "ciphertext": b64(b"w" * 48)},
        "vault": {"version": version, "nonce": b64(b"v" * 24), "ciphertext": b64(b"c" * 40)},
    }


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def test_register_login_get_put(http):
    r = http.post("/register", json=register_body())
    assert r.status_code == 201
    r = http.post("/login", json={"email": "ANA@utec.edu.pe ", "auth_key": b64(AUTH_KEY)})
    assert r.status_code == 200
    token = r.json()["token"]

    r = http.get("/vault", headers=auth_header(token))
    assert r.status_code == 200 and r.json()["version"] == 1

    put = {"version": 2, "nonce": b64(b"x" * 24), "ciphertext": b64(b"y" * 50)}
    r = http.put("/vault", json=put, headers=auth_header(token))
    assert r.status_code == 200 and r.json()["version"] == 2

    # Reenviar la misma versión (replay o escritura concurrente) → 409
    r = http.put("/vault", json=put, headers=auth_header(token))
    assert r.status_code == 409
    # Intentar retroceder → 409
    r = http.put("/vault", json={**put, "version": 1}, headers=auth_header(token))
    assert r.status_code == 409
    # Saltar versiones → 409
    r = http.put("/vault", json={**put, "version": 9}, headers=auth_header(token))
    assert r.status_code == 409
    assert http.get("/vault", headers=auth_header(token)).json()["version"] == 2


def test_duplicate_register(http):
    assert http.post("/register", json=register_body()).status_code == 201
    assert http.post("/register", json=register_body()).status_code == 409


def test_register_validates_sizes_and_params(http):
    body = register_body()
    body["auth_key"] = b64(b"short")
    assert http.post("/register", json=body).status_code == 422
    body = register_body()
    body["kdf_params"]["memory_kib"] = 8
    assert http.post("/register", json=body).status_code == 422
    assert http.post("/register", json=register_body(version=5)).status_code == 422


def test_wrong_auth_key_and_unknown_user_are_indistinguishable(http):
    http.post("/register", json=register_body())
    r1 = http.post("/login", json={"email": "ana@utec.edu.pe", "auth_key": b64(b"B" * 32)})
    r2 = http.post("/login", json={"email": "nadie@utec.edu.pe", "auth_key": b64(b"B" * 32)})
    assert r1.status_code == r2.status_code == 401
    assert r1.json() == r2.json()


def test_vault_requires_valid_token(http):
    assert http.get("/vault").status_code == 401
    assert http.get("/vault", headers=auth_header("inventado")).status_code == 401


def test_rate_limit_after_failures(http):
    http.post("/register", json=register_body())
    bad = {"email": "ana@utec.edu.pe", "auth_key": b64(b"B" * 32)}
    for _ in range(3):
        assert http.post("/login", json=bad).status_code == 401
    # Bloqueado incluso con la llave correcta
    good = {"email": "ana@utec.edu.pe", "auth_key": b64(AUTH_KEY)}
    assert http.post("/login", json=good).status_code == 429


def test_kdf_params_do_not_reveal_existence(http):
    http.post("/register", json=register_body())
    real = http.get("/kdf-params", params={"email": "ana@utec.edu.pe"}).json()
    fake1 = http.get("/kdf-params", params={"email": "nadie@utec.edu.pe"}).json()
    fake2 = http.get("/kdf-params", params={"email": "nadie@utec.edu.pe"}).json()
    assert real["salt_kdf"] == b64(b"s" * 16)
    assert fake1 == fake2  # determinista: consultar dos veces no delata
    assert len(base64.b64decode(fake1["salt_kdf"])) == 16


def test_server_stores_no_auth_key_and_hashed_tokens(app, http):
    token = http.post("/register", json=register_body()).json()["token"]
    with app.state.SessionLocal() as db:
        user = db.scalar(select(User))
        assert user.auth_hash.startswith("$argon2id$")
        assert b64(AUTH_KEY) not in user.auth_hash
        stored = db.scalar(select(SessionToken))
        assert stored.token_hash != token and len(stored.token_hash) == 64


def test_security_headers(http):
    r = http.get("/kdf-params", params={"email": "x@y.z"})
    assert "max-age" in r.headers["strict-transport-security"]
    assert r.headers["cache-control"] == "no-store"
