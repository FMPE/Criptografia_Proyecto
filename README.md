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

# Cliente de escritorio, Flet 1.1.2 (otra terminal)
.venv\Scripts\python -m client.ui.app

# Pruebas y análisis estático
.venv\Scripts\python -m pytest -q
.venv\Scripts\bandit -r client server
.venv\Scripts\pip-audit -r requirements-client.txt -r requirements-server.txt
```

La primera vez que se abre el cliente, `flet-desktop` descarga su aplicación nativa
(unos segundos, una sola vez). Para esa descarga la app usa las CAs de `certifi`,
porque el Python de Anaconda trae CAs desactualizadas. La conexión con el servidor
propio no cambia: sigue confiando solo en `PM_CA_CERT`.

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
| Passkeys Ed25519: par generado en el cliente, privada guardada en la bóveda (bajo VK) | [client/crypto/passkeys.py](client/crypto/passkeys.py), [client/vault/models.py](client/vault/models.py) |
| Challenge de un solo uso, prueba de posesión al registrar, verificación de firma | [server/app/passkeys.py](server/app/passkeys.py) |

### Passkeys

Mensajes firmados (con etiqueta de dominio y prefijo de longitud):

- login: `enc("pm-passkey-auth-v1", email, challenge_id, challenge)`
- registro: `enc("pm-passkey-register-v1", email, public_key)`, como prueba de posesión

El challenge (32 B, TTL 60 s) se borra **antes** de verificar la firma, así que es
de un solo uso aunque la firma falle. Como la llave privada vive dentro de la bóveda,
la passkey solo se usa con la bóveda ya abierta. Sirve para dos cosas:

1. **Renovar la sesión:** si el token expira, `save()` y `pull()` se re-autentican
   con la passkey sin pedir la contraseña.
2. **Desbloquear con passkey** en un dispositivo ya usado: la bóveda se abre desde la
   caché local y el servidor solo recibe la firma. **AuthKey nunca viaja.**

## API

| Endpoint | Descripción |
|---|---|
| `POST /register` | email, salt_kdf, kdf_params, AuthKey, VK envuelta, blob v1 → token |
| `GET /kdf-params?email=` | salt_kdf y parámetros (salt falso determinista si el correo no existe) |
| `POST /login` | verifica Argon2id(AuthKey) → token (15 min) |
| `GET /vault` | blob, nonce, versión y VK envuelta |
| `PUT /vault` | acepta sólo `versión == actual + 1`, si no 409 |
| `POST /passkeys` | registra una llave pública Ed25519 (requiere sesión y prueba de posesión) |
| `GET /passkeys` | lista las passkeys de la cuenta |
| `DELETE /passkeys/{id}` | revoca una passkey |
| `POST /auth/challenge` | challenge de 32 B, un solo uso, 60 s (misma respuesta si el correo no existe) |
| `POST /auth/verify` | verifica la firma Ed25519 → token |

## Estado

- **P0 (hecho):** motor criptográfico, bóveda (crear/editar/duplicar/eliminar/buscar/filtrar por etiqueta), generador, servidor (registro, login, blob), TLS 1.3, UI de escritorio en Flet, CI con bandit + semgrep + pip-audit.
- **P1 (hecho):** passkeys Ed25519 con challenge-response (crear, revocar, renovar la sesión, desbloquear sin enviar AuthKey).
- **P1 (pendiente):** verificación local anti-rollback (la versión ya está en el AAD, falta que el cliente recuerde la última versión vista), cambio de contraseña maestra, bloqueo automático y limpieza del portapapeles.
- **P2:** certificate pinning por huella, padding del blob, exportación cifrada, Docker Compose.

## Limitaciones conocidas de la UI

- **Proceso de interfaz separado.** Flet dibuja la ventana en un proceso de Flutter
  distinto del proceso de Python, y ambos se comunican por un canal local. Todo lo que
  se ve en pantalla pasa por ese canal: entradas, contraseñas reveladas o copiadas y la
  Secret Key del kit de emergencia. Un malware con acceso a la sesión del usuario ya
  podría leer la pantalla o la memoria (ver "cliente comprometido" en el informe), pero
  el canal es una superficie más que con una UI en un solo proceso.
- **Limpieza del portapapeles pendiente (P1).** Todo copiado pasa por
  [client/ui/clipboard.py](client/ui/clipboard.py); ahí va la limpieza temporizada.
