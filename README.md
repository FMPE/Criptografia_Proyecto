# Gestor de contraseñas E2E (zero-knowledge)

Proyecto del curso de Criptografía (UTEC). Toda la criptografía ocurre en el
cliente; el servidor sólo guarda un blob opaco autenticado.

## Puesta en marcha

```powershell
py -3.10 -m venv .venv
.venv\Scripts\pip install -r requirements-dev.txt

# Servidor (TLS 1.3 con certificado autofirmado)
.venv\Scripts\python -m server.scripts.gen_cert     # una vez
.venv\Scripts\python -m server.app.main              # https://127.0.0.1:8443

# Cliente de escritorio (otra terminal)
.venv\Scripts\python -m client.ui.app

# Pruebas y análisis estático
.venv\Scripts\python -m pytest -q
.venv\Scripts\bandit -r client server
.venv\Scripts\pip-audit -r requirements-client.txt -r requirements-server.txt
```

Variables útiles: `PM_SERVER_URL`, `PM_CA_CERT`, `PM_HOME` (cliente);
`PM_DATABASE_URL`, `PM_FAKE_SALT_KEY` (hex de 32 B), `PM_TOKEN_TTL` (servidor).
Por defecto el servidor usa SQLite; para PostgreSQL basta con
`PM_DATABASE_URL=postgresql+psycopg://...`.

## Criptografía (dónde está cada cosa)

| Qué | Dónde |
|---|---|
| `salt = HKDF-Extract(salt_kdf, SecretKey)`; `MK = Argon2id(maestra, salt)` (64 MiB, t=3, p=4) | [client/crypto/kdf.py](client/crypto/kdf.py) |
| `AuthKey = HKDF-Expand(MK, "auth")`, `KEK = HKDF-Expand(MK, "vault-kek")` | [client/crypto/kdf.py](client/crypto/kdf.py) |
| XChaCha20-Poly1305 con nonce de 192 bits generado **dentro** de `encrypt` | [client/crypto/aead.py](client/crypto/aead.py) |
| Secret Key (256 bits, formato `PM1-…` con checksum), VK y key wrapping | [client/crypto/keys.py](client/crypto/keys.py) |
| Blob de la bóveda con `AAD = "vault" ‖ versión ‖ user_id` | [client/vault/blob.py](client/vault/blob.py) |
| Generador con `secrets` | [client/crypto/generator.py](client/crypto/generator.py) |
| Flujos de registro / desbloqueo / guardado | [client/vault/manager.py](client/vault/manager.py) |
| `Argon2id(AuthKey, salt_srv)`, tokens hasheados, rate limiting | [server/app/security.py](server/app/security.py) |
| PUT con versión esperada atómica (409 si no coincide) | [server/app/vault.py](server/app/vault.py) |

## API

| Endpoint | Descripción |
|---|---|
| `POST /register` | email, salt_kdf, kdf_params, AuthKey, VK envuelta, blob v1 → token |
| `GET /kdf-params?email=` | salt_kdf y parámetros (salt falso determinista si el correo no existe) |
| `POST /login` | verifica Argon2id(AuthKey) → token (15 min) |
| `GET /vault` | blob, nonce, versión y VK envuelta |
| `PUT /vault` | acepta sólo `versión == actual + 1`, si no 409 |

## Estado

- **P0 (hecho):** motor criptográfico, bóveda (crear/editar/duplicar/eliminar/buscar/filtrar por etiqueta), generador, servidor (registro, login, blob), TLS 1.3, UI PySide6, CI con bandit + semgrep + pip-audit.
- **P1 (pendiente):** passkeys Ed25519 (`client/crypto/passkeys.py`, `server/app/passkeys.py` son stubs), verificación local anti-rollback (la versión ya está en el AAD, falta que el cliente recuerde la última versión vista), cambio de contraseña maestra, bloqueo automático y limpieza del portapapeles.
- **P2:** certificate pinning por huella, padding del blob, exportación cifrada, Docker Compose.
