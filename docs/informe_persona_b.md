# Informe — secciones de la Persona B

Secciones: jerarquía de llaves, cambio de contraseña maestra, protección en reposo y
limitaciones. Las referencias apuntan al código del repositorio.

---

## 1. Jerarquía de llaves

```
contraseña maestra ─┐
                    ├─ Argon2id (m = 64 MiB, t = 3, p = 4) ──► MK (32 B, nunca se guarda)
Secret Key (256 b) ─┤                                            │
salt_kdf (16 B) ────┘ salt = HKDF-Extract(salt_kdf, SecretKey)   ├─ HKDF-Expand("auth")      ──► AuthKey ──► servidor: Argon2id(AuthKey, salt_srv)
                                                                 └─ HKDF-Expand("vault-kek") ──► KEK
                                                                                                  │ XChaCha20-Poly1305, AAD = "vk-wrap" ‖ user_id
                                                                                                  ▼
                                                     VK (256 b, aleatoria, fija durante la vida de la cuenta)
                                                                                                  │ XChaCha20-Poly1305, AAD = "vault" ‖ versión ‖ user_id
                                                                                                  ▼
                                                              blob = pad(JSON de la bóveda)  (entradas + llaves privadas de passkeys)
```

| Llave | Origen | Dónde vive | Quién la conoce |
|---|---|---|---|
| Contraseña maestra | el usuario | sólo en su memoria | el usuario |
| Secret Key | `secrets.token_bytes(32)` al registrarse | `~/.pwmanager/<hash>/secret_key` (0600) y kit de emergencia | el usuario / sus dispositivos |
| MK | Argon2id | sólo en RAM durante la derivación | nadie (se descarta) |
| AuthKey | HKDF(MK, "auth") | viaja al servidor por TLS 1.3 | el servidor sólo guarda Argon2id(AuthKey) |
| KEK | HKDF(MK, "vault-kek") | sólo en RAM | sólo el cliente |
| VK | aleatoria | envuelta con KEK (servidor y caché local); en claro sólo en RAM con la bóveda abierta | sólo el cliente |
| Llave de respaldo | Argon2id(contraseña de respaldo, salt nuevo) → HKDF("pm-export-v1") | sólo en RAM al exportar/importar | quien tenga la contraseña de respaldo |

Por qué una VK intermedia: la bóveda se cifra con una llave que **no** depende de la
contraseña. Cambiar la contraseña sólo re-envuelve 32 bytes; la bóveda (que puede pesar
megabytes y está versionada) no se toca. La separación de dominio con `info` distintos en
HKDF garantiza que conocer AuthKey (que sí llega al servidor) no revela nada de KEK.

---

## 2. Cambio de contraseña maestra

Implementación: `VaultManager.change_password(old, new)`
([client/vault/manager.py](../client/vault/manager.py)), endpoint
`POST /account/password` ([server/app/auth.py](../server/app/auth.py)) y diálogo
`ChangePasswordDialog` ([client/ui/account_dialogs.py](../client/ui/account_dialogs.py)).

### Protocolo

1. El cliente exige estar en línea y con la bóveda abierta (tiene la VK en RAM).
2. Valida la contraseña nueva (≥ 12 caracteres, ≥ 50 bits estimados, distinta de la actual).
3. Pide al servidor el `salt_kdf` y los parámetros **actuales** (no los de la caché local,
   que podrían estar desactualizados si otro dispositivo cambió la contraseña) y los valida
   con `check_params`.
4. Deriva `AuthKey_vieja` con la contraseña actual.
5. Genera un `salt_kdf` **nuevo** y deriva `AuthKey_nueva` y `KEK_nueva` con la contraseña
   nueva y la misma Secret Key.
6. `VK_envuelta' = XChaCha20-Poly1305(KEK_nueva, VK, nonce nuevo, AAD = "vk-wrap" ‖ user_id)`.
7. Envía `{old_auth_key, new_auth_key, salt_kdf', kdf_params, VK_envuelta'}` con el token de sesión.
8. El servidor:
   - exige el token **y** verifica `Argon2id(AuthKey_vieja)` contra el hash guardado (un token
     robado no basta para secuestrar la cuenta). Los fallos cuentan para el rate limiting del
     login; un fallo responde **403** (no 401) para no confundirse con una sesión vencida;
   - rechaza parámetros por debajo del mínimo y una contraseña nueva igual a la actual;
   - reemplaza en una sola transacción `auth_hash`, `salt_kdf`, parámetros y la VK envuelta;
   - **borra todas las sesiones de la cuenta** y emite un token nuevo sólo para quien hizo el cambio.
9. El cliente actualiza `account.json` (salt nuevo) y la VK envuelta de `cache.json`, para que
   el desbloqueo sin conexión en este dispositivo use la contraseña nueva.

### Qué NO cambia (verificado en `tests/test_change_password.py`)

- El blob de la bóveda: misma versión, mismo nonce, mismo ciphertext, byte a byte.
- La VK: la envuelta nueva es distinta, pero desenvuelve a la misma VK.
- La Secret Key.

### Decisión: el cambio de contraseña invalida las sesiones activas

**Sí, en todos los dispositivos.** Motivo: la razón más común para cambiar la contraseña es
sospechar que se filtró. Si la contraseña se filtró, también pudo filtrarse un token de sesión
obtenido con ella; dejarlo vivo (hasta 15 min) contradice la intención del usuario.

Consecuencias para los otros dispositivos:

| Situación del otro dispositivo | Qué pasa |
|---|---|
| Bloqueado, en línea | La contraseña vieja falla (el servidor tiene el hash nuevo). Con la nueva, descarga el salt y la VK envuelta nuevos y actualiza su caché. |
| Abierto, sin passkey | Su próximo `save()`/`pull()` recibe 401 → `SessionExpiredError`: debe volver a desbloquear con la contraseña nueva. |
| Abierto, con passkey | `_authenticated` se re-autentica con la passkey (firma Ed25519) y sigue. Es coherente con el modelo de passkeys: la privada está dentro de la bóveda, así que quien la tiene ya tiene la VK. **Si el motivo del cambio es un dispositivo perdido, hay que revocar también su passkey.** |
| Bloqueado, sin conexión | Ver limitación L2. |

---

## 3. Protección en reposo

### 3.1 Servidor
Sólo guarda: `salt_kdf` y parámetros (públicos), `Argon2id(AuthKey, salt_srv)`, la VK envuelta
y el blob cifrado. Ninguno permite descifrar sin la contraseña **y** la Secret Key. Los tokens
de sesión se guardan como SHA-256.

### 3.2 Padding del blob ([client/vault/blob.py](../client/vault/blob.py))
XChaCha20-Poly1305 es un cifrado de flujo: `|ct| = |texto| + 16`. Sin relleno, el servidor
vería crecer el blob con cada entrada nueva y podría estimar cuántas hay y cuándo se agregan.
Antes de cifrar:

```
pad(x) = 0x01 ‖ len(x) (u32 BE) ‖ x ‖ 0x00…  hasta un múltiplo de 4096 B
```

- El relleno está **dentro** del AEAD, así que está autenticado; `unpad` además exige que los
  bytes de relleno sean cero.
- El byte `0x01` marca el formato nuevo. Un JSON empieza con `{`, así que las bóvedas selladas
  antes del cambio se siguen abriendo (compatibilidad hacia atrás).
- Prueba: una bóveda con 0 a 9 entradas produce siempre un ciphertext de 4096 + 16 B
  (`test_size_does_not_reveal_number_of_entries`).

### 3.3 Dispositivo
- `secret_key`, `account.json`, `cache.json`, `max_version.json` y `preferences.json` se escriben
  atómicamente con permisos 0600. La caché está cifrada igual que en el servidor.
- **Bloqueo automático** ([client/ui/idle.py](../client/ui/idle.py)): un temporizador de
  inactividad (5 min por defecto, configurable entre 30 s y 1 h) bloquea la bóveda: cierra los
  diálogos, limpia el portapapeles, olvida VK y bóveda en claro y vuelve al login. Cuenta como
  actividad el teclado, el mouse y la rueda en toda la ventana; mientras corre una operación
  larga (Argon2id, red) no se bloquea. El bloqueo ocurre aunque haya cambios sin subir (se avisa).
- **Portapapeles** ([client/ui/clipboard.py](../client/ui/clipboard.py)): cada copia programa
  una limpieza a los N s (30 s por defecto, configurable entre 5 s y 5 min). Al vencer se lee el
  portapapeles y **sólo se borra si todavía contiene lo que copió la app**; para comparar se
  guarda SHA-256 del texto, no el texto. Una copia nueva reinicia el temporizador. También se
  limpia al bloquear y al cerrar la ventana.
- Las preferencias son por dispositivo (`<PM_HOME>/preferences.json`) y se acotan al rango
  seguro aunque el archivo se edite a mano.

### 3.4 Respaldo cifrado `.pmx` ([client/vault/export.py](../client/vault/export.py))
Independiente de la cuenta, para poder guardarlo fuera o restaurarlo en otra cuenta:

```
salt  = 16 B aleatorios (nuevos en cada exportación)
K     = HKDF-Expand(Argon2id(contraseña_respaldo, salt), "pm-export-v1")
AAD   = enc("pm-export-v1", formato ‖ m ‖ t ‖ p, salt)
ct    = XChaCha20-Poly1305(K, pad(JSON(entradas)), nonce nuevo de 24 B, AAD)
archivo = JSON {magic, format, kdf{alg, m, t, p, salt}, nonce, ciphertext}
```

- Todo el encabezado entra en el AAD: alterar el ciphertext, el nonce, el salt o los
  parámetros hace fallar el tag (`test_tampered_file_is_detected`).
- Al importar se rechazan parámetros por debajo del mínimo o absurdamente altos (un archivo
  fabricado no puede abaratar la fuerza bruta ni colgar el cliente).
- La contraseña de respaldo pasa la misma política que la maestra.
- **No se exportan las passkeys**: su privada sólo sirve para la cuenta donde se registró.
- La importación **agrega** entradas: omite las idénticas y, si un id coincide con contenido
  distinto, la agrega como entrada nueva. Nunca sobrescribe. Luego sube la bóveda.

---

## 4. Limitaciones

- **L1. La VK no rota.** Cambiar la contraseña no cambia la VK. Quien ya obtuvo la VK (p. ej.
  malware en un dispositivo con la bóveda abierta, o quien copió la caché **y** conocía la
  contraseña vieja y la Secret Key) puede seguir descifrando versiones futuras del blob. Rotar
  la VK exigiría re-cifrar la bóveda y re-envolver en todos los dispositivos; se dejó fuera del
  alcance. Si se sospecha que la Secret Key también se filtró, la contraseña nueva no basta.
- **L2. Cachés sin conexión con la contraseña vieja.** Un dispositivo que no se conecta desde el
  cambio guarda el salt y la VK envuelta viejos, así que **sin conexión** se sigue abriendo con
  la contraseña vieja (y sólo lectura) hasta que se conecte una vez. Es inherente a permitir el
  desbloqueo offline.
- **L3. Respuesta perdida.** Si el servidor aplica el cambio pero la respuesta no llega, el
  dispositivo queda con su caché vieja: en línea se corrige solo en el siguiente desbloqueo
  (descarga el salt nuevo); sin conexión aplica L2.
- **L4. Servidor malicioso.** Puede negarse a aplicar el cambio o servir la VK envuelta vieja con
  el salt viejo (la contraseña vieja seguiría funcionando en un dispositivo nuevo). No puede
  descifrar nada, pero el cambio de contraseña depende de su cooperación.
- **L5. Memoria.** Python no permite borrar con garantía objetos `bytes`/`str` inmutables: al
  bloquear se sueltan las referencias (VK, bóveda), pero los datos pueden quedar en RAM hasta
  que se reutilice esa memoria. Lo mismo para las contraseñas escritas en la UI (que además
  pasan por el proceso de Flutter).
- **L6. Bloqueo automático.** Depende de que el bucle de la UI siga vivo; no protege contra
  quien ya tiene acceso a la sesión del sistema operativo mientras la bóveda está abierta. No se
  bloquea al minimizar la ventana, sólo por tiempo.
- **L7. Portapapeles.** Los gestores de historial del SO (Win + V en Windows, sincronización en
  la nube del portapapeles) pueden conservar una copia que la app no puede borrar. La limpieza
  sólo actúa sobre el contenido actual.
- **L8. Padding.** Oculta el número de entradas dentro de bloques de 4 KiB, no el orden de
  magnitud: una bóveda de 200 entradas sigue siendo más grande que una de 5. Tampoco oculta
  *cuándo* se guarda (la versión y la hora del PUT son visibles).
- **L9. Respaldo.** Su seguridad depende de la contraseña de respaldo y de que se guarde aparte.
  No tiene anti-rollback (un respaldo viejo es válido por definición) ni está ligado a la cuenta.
