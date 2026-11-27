# Guion de la demo (Entrega 2)

Cada paso muestra **la criptografía**, no sólo que la app funciona. Todos los comandos se
ejecutan desde `password-manager/` con el venv. Todo lo de la demo vive en `demo/data/`.

## Antes de presentar

Abre tres terminales:

| Terminal | Comando | Para qué |
|---|---|---|
| A: servidor | `.venv\Scripts\python -m demo servidor --reset` | Servidor TLS 1.3 con una BD limpia. Deja visible su log. |
| B: cliente | `.venv\Scripts\python -m demo app --rapido` | La app (bloqueo a los 30 s, portapapeles a los 5 s). |
| C: "servidor malicioso" | `.venv\Scripts\python -m demo bd` | Ver y manipular la base de datos del servidor. |

Si es la primera vez en la máquina: `.venv\Scripts\python -m server.scripts.gen_cert`.
Ensaya una vez completa: el primer arranque de Flet descarga su cliente de escritorio.

Ten listas una contraseña maestra (p. ej. `Tr3s-Tristes-Tigres!`) y una nueva para el paso 8.

## Pasos

**1. Registro: el servidor no aprende nada (zero-knowledge).**
En la app: *Crear cuenta*. Se muestra el kit de emergencia: copia la Secret Key a un bloc de
notas (la necesitas en el paso 3). Agrega una entrada, por ejemplo `banco.pe` con contraseña
`MiClaveBancaria2026`, y guarda.
```
python -m demo bd --buscar banco.pe MiClaveBancaria2026 "Tr3s-Tristes-Tigres!" PM1-...
```
Señala: el verificador es `$argon2id$...` de la AuthKey (no de la contraseña), la VK está
envuelta, el blob es opaco, y **ningún** texto buscado aparece. Tampoco la Secret Key.

**2. Versión y padding.**
Agrega 3 o 4 entradas más (cada una se sube) y vuelve a ejecutar `python -m demo bd`.
La versión sube (`<< CAMBIÓ`), pero el tamaño sigue en **4112 B**: el relleno a bloques de 4 KiB
oculta cuántas entradas hay.

**3. La Secret Key es un segundo secreto real.**
En otra terminal: `python -m demo app --dispositivo pc-nueva`. Desbloquea con el correo y la
contraseña **correctos**: la app pide la Secret Key. Pega una inventada: no entra (o el
checksum detecta el error de tipeo). Pega la real: entra. Cierra esa ventana.

**4. Manipulación del blob (integridad AEAD).**
```
python -m demo alterar
```
Cambia **un bit** del ciphertext en el servidor. En la app: *Bloquear* y volver a desbloquear:
"La bóveda no pasó la verificación de integridad" (falla el tag Poly1305).
```
python -m demo restaurar
```

**5. Rollback (servidor que devuelve una versión vieja pero íntegra).**
```
python -m demo guardar-version
```
En la app agrega dos entradas más (la versión sube dos veces). Luego:
```
python -m demo rollback
```
En la app: *Bloquear* y desbloquear: "Posible ataque de rollback: el servidor devolvió la
versión vN, pero este dispositivo ya verificó la vM". Explica las dos capas: la versión va en
el AAD (no se puede relabelar) y el cliente recuerda la versión más alta que vio.
```
python -m demo restaurar
```

**6. MITM detectado por el pin.**
Cierra la app y ábrela con `python -m demo app --pin-incorrecto`. Al desbloquear: "La llave
pública del servidor no coincide con el pin configurado... Posible ataque MITM". Señala que
**no** abrió la caché en modo sin conexión. Para el escenario de una CA comprometida, muestra
`python -m pytest tests/test_pinning.py -v` (servidores TLS reales: sin pin el MITM funciona,
con pin no le llega ni una petición). Vuelve a abrir la app normal (`--rapido`).

**7. Passkey: login sin enviar AuthKey.**
En la app: icono de huella → *Crear* (etiqueta "laptop") → *Probar login*. Bloquea y desbloquea
con el interruptor *Usar passkey*. En el log del servidor (terminal A) aparecen
`POST /auth/challenge` y `POST /auth/verify`, y **no** `POST /login`.

**8. Cambio de contraseña sin re-cifrar la bóveda.**
Ejecuta `python -m demo bd` (deja las huellas de referencia). En la app: menú de cuenta →
*Cambiar contraseña maestra*. Vuelve a ejecutar `python -m demo bd`:
`VK envuelta ... << CAMBIÓ`, pero `bóveda: ciphertext ... (sin cambios)` y la misma versión.
Bloquea: la contraseña vieja ya no entra, la nueva sí.

**9. Higiene en el equipo.**
Copia una contraseña: el aviso dice que se borrará en 5 s; pégala en el bloc de notas pasado
ese tiempo: ya no está. Deja la app quieta 30 s: se bloquea sola y vuelve al login.

## Si algo sale mal

- Quedó un blob alterado o viejo en el servidor: `python -m demo restaurar`.
- Empezar de cero: detén el servidor y vuelve a lanzarlo con `--reset`.
- Hay varias cuentas en la BD: agrega `--email tu@correo` a `guardar-version`, `rollback` y
  `alterar`.
