"""Herramientas para la demo en vivo.  Uso:  python -m demo <comando>

  servidor [--reset]        Levanta el servidor TLS con una base de datos sólo para la demo.
  app [--dispositivo N]     Abre el cliente como el dispositivo N (cada uno con su propio
      [--pin-incorrecto]    almacén local). --pin-incorrecto simula un servidor con otra llave;
      [--rapido]            --rapido deja el bloqueo en 30 s y el portapapeles en 5 s.
  bd [--buscar TEXTO ...]   Muestra lo que REALMENTE guarda el servidor y busca textos en claro.
  guardar-version           Guarda una copia de la bóveda tal como está ahora en el servidor.
  rollback                  El "servidor malicioso" vuelve a servir la copia guardada.
  alterar                   El "servidor malicioso" cambia un byte del blob cifrado.
  restaurar                 Deshace rollback/alterar: el servidor vuelve a la última versión.

Todo vive en demo/data/ (base de datos, dispositivos y copias); --reset lo borra.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess  # nosec B404 - sólo lanza este mismo proyecto con sys.executable
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "demo" / "data"
DB = DATA / "server.db"
DEVICES = DATA / "dispositivos"
SNAPSHOT = DATA / "version_guardada.json"
LATEST = DATA / "ultima_version.json"
FINGERPRINTS = DATA / "huellas.json"

WRONG_PIN = "sha256//" + base64.b64encode(b"\x00" * 32).decode("ascii")


def say(text: str = "") -> None:
    print(text, flush=True)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def hexs(data: bytes, n: int = 16) -> str:
    return data[:n].hex() + ("..." if len(data) > n else "")


# --------------------------------------------------------------------------- #
# Procesos
# --------------------------------------------------------------------------- #
def run_module(module: str, env: dict) -> int:
    full_env = {**os.environ, **env}
    try:
        return subprocess.call([sys.executable, "-m", module], cwd=REPO, env=full_env)  # nosec B603
    except KeyboardInterrupt:
        return 0


def cmd_servidor(args) -> int:
    if args.reset and DATA.exists():
        shutil.rmtree(DATA)
        say("Se borraron la base de datos y los dispositivos de la demo.")
    DATA.mkdir(parents=True, exist_ok=True)
    if not (REPO / "server" / "certs" / "cert.pem").exists():
        say("Falta el certificado. Ejecuta primero: python -m server.scripts.gen_cert")
        return 1
    say(f"Base de datos de la demo: {DB}")
    say("Cada petición aparece abajo (útil para ver /login frente a /auth/verify).")
    say("Ctrl+C para detener.\n")
    return run_module("server.app.main", {"PM_DATABASE_URL": f"sqlite:///{DB.as_posix()}"})


def cmd_app(args) -> int:
    home = DEVICES / args.dispositivo
    home.mkdir(parents=True, exist_ok=True)
    env = {"PM_HOME": str(home)}
    if args.pin_incorrecto:
        env["PM_PINS"] = WRONG_PIN
        say(f"Pin configurado: {WRONG_PIN}")
        say("(no coincide con la llave pública del servidor: el cliente debe rechazar la conexión)")
    if args.rapido:
        prefs = {"auto_lock_seconds": 30, "clipboard_clear_seconds": 5}
        (home / "preferences.json").write_text(json.dumps(prefs), "utf-8")
        say("Preferencias de la demo: bloqueo tras 30 s de inactividad, portapapeles a los 5 s.")
    say(f"Dispositivo '{args.dispositivo}' -> almacén local en {home}")
    return run_module("client.ui.app", env)


# --------------------------------------------------------------------------- #
# Base de datos del servidor
# --------------------------------------------------------------------------- #
def connect() -> sqlite3.Connection:
    if not DB.exists():
        raise SystemExit("No hay base de datos de la demo. Ejecuta: python -m demo servidor")
    return sqlite3.connect(DB)


def pick_user(con: sqlite3.Connection, email: str | None) -> tuple[int, str]:
    rows = con.execute("SELECT id, email FROM users ORDER BY id").fetchall()
    if not rows:
        raise SystemExit("Todavía no hay cuentas registradas.")
    if email:
        for uid, e in rows:
            if e == email.strip().lower():
                return uid, e
        raise SystemExit(f"No existe la cuenta {email}")
    if len(rows) > 1:
        raise SystemExit("Hay varias cuentas; indica cuál con --email")
    return rows[0]


def read_vault(con: sqlite3.Connection, uid: int) -> dict:
    version, nonce, ct = con.execute(
        "SELECT version, nonce, ciphertext FROM vaults WHERE user_id = ?", (uid,)
    ).fetchone()
    return {"version": version, "nonce": bytes(nonce).hex(), "ciphertext": bytes(ct).hex()}


def write_vault(con: sqlite3.Connection, uid: int, row: dict) -> None:
    con.execute(
        "UPDATE vaults SET version = ?, nonce = ?, ciphertext = ? WHERE user_id = ?",
        (row["version"], bytes.fromhex(row["nonce"]), bytes.fromhex(row["ciphertext"]), uid),
    )
    con.commit()


def changed(key: str, value: str, old: dict, new: dict) -> str:
    new[key] = value
    if key not in old:
        return ""
    return "   (sin cambios)" if old[key] == value else "   << CAMBIÓ"


def cmd_bd(args) -> int:
    con = connect()
    old = json.loads(FINGERPRINTS.read_text("utf-8")) if FINGERPRINTS.exists() else {}
    new: dict = {}
    say("=" * 78)
    say(" Lo que guarda el servidor (base de datos de la demo)")
    say("=" * 78)
    users = con.execute(
        "SELECT id, email, salt_kdf, kdf_memory_kib, kdf_time_cost, kdf_parallelism, "
        "auth_hash, wrapped_vk_nonce, wrapped_vk FROM users ORDER BY id"
    ).fetchall()
    if not users:
        say("No hay cuentas registradas.")
    for uid, email, salt, m, t, p, auth_hash, wnonce, wvk in users:
        wvk = bytes(wvk)
        say(f"\nCuenta: {email}")
        say(f"  salt_kdf (público)        {bytes(salt).hex()}")
        say(f"  parámetros Argon2id       m={m} KiB, t={t}, p={p}")
        say(f"  verificador de AuthKey    {auth_hash[:60]}...")
        say(f"  VK envuelta ({len(wvk)} B)      {hexs(wvk)}   SHA-256 {sha(wvk)}"
            + changed(f"{email}/wvk", sha(wvk), old, new))
        row = con.execute(
            "SELECT version, nonce, ciphertext FROM vaults WHERE user_id = ?", (uid,)
        ).fetchone()
        if row:
            version, nonce, ct = row[0], bytes(row[1]), bytes(row[2])
            say(f"  bóveda: versión           v{version}" + changed(f"{email}/ver", str(version), old, new))
            say(f"  bóveda: tamaño            {len(ct)} B   (relleno a bloques de 4 KiB + 16 B de tag)")
            say(f"  bóveda: nonce             {nonce.hex()}")
            say(f"  bóveda: ciphertext        {hexs(ct)}   SHA-256 {sha(ct)}"
                + changed(f"{email}/ct", sha(ct), old, new))
        pks = con.execute(
            "SELECT id, label, public_key FROM passkeys WHERE user_id = ?", (uid,)
        ).fetchall()
        for pid, label, pub in pks:
            say(f"  passkey #{pid} '{label}'       llave PÚBLICA {bytes(pub).hex()[:32]}...")
        n_sessions = con.execute("SELECT COUNT(*) FROM sessions WHERE user_id = ?", (uid,)).fetchone()[0]
        say(f"  sesiones activas          {n_sessions} (se guarda SHA-256 del token, no el token)")
    FINGERPRINTS.write_text(json.dumps({**old, **new}), "utf-8")

    if args.buscar:
        say("\nBúsqueda de texto en claro en TODA la base de datos:")
        blobs = []
        for (table,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'"):
            for row in con.execute(f'SELECT * FROM "{table}"'):  # nosec B608 - nombres de sqlite_master
                for value in row:
                    if isinstance(value, (bytes, memoryview)):
                        blobs.append(bytes(value))
                    elif isinstance(value, str):
                        blobs.append(value.encode("utf-8"))
        for term in args.buscar:
            needle = term.encode("utf-8")
            found = any(needle in b or needle.lower() in b.lower() for b in blobs)
            say(f"  '{term}': {'ENCONTRADO' if found else 'no aparece'}")
    say("")
    return 0


# --------------------------------------------------------------------------- #
# Servidor malicioso
# --------------------------------------------------------------------------- #
def cmd_guardar_version(args) -> int:
    con = connect()
    uid, email = pick_user(con, args.email)
    row = read_vault(con, uid)
    SNAPSHOT.write_text(json.dumps({"email": email, **row}), "utf-8")
    say(f"Copia guardada de la bóveda de {email}: v{row['version']}.")
    say("Ahora haz más cambios en la app (v+1, v+2...) y luego ejecuta: python -m demo rollback")
    return 0


def _backup_latest(con, uid, email) -> dict:
    current = read_vault(con, uid)
    if not LATEST.exists():  # conservar la primera "verdad" si se encadenan ataques
        LATEST.write_text(json.dumps({"email": email, **current}), "utf-8")
    return current


def cmd_rollback(args) -> int:
    if not SNAPSHOT.exists():
        raise SystemExit("Primero guarda una versión: python -m demo guardar-version")
    con = connect()
    snap = json.loads(SNAPSHOT.read_text("utf-8"))
    uid, email = pick_user(con, snap["email"])
    current = _backup_latest(con, uid, email)
    if snap["version"] >= current["version"]:
        raise SystemExit(
            f"La copia (v{snap['version']}) no es más vieja que la actual (v{current['version']}): "
            "guarda cambios en la app antes del rollback."
        )
    write_vault(con, uid, snap)
    say(f"El servidor ahora sirve la bóveda v{snap['version']} (la última era v{current['version']}).")
    say("El blob es ÍNTEGRO: su tag Poly1305 valida. Bloquea y desbloquea en la app:")
    say("el cliente debe rechazarlo con un aviso de rollback.")
    say("Para volver a la normalidad: python -m demo restaurar")
    return 0


def cmd_alterar(args) -> int:
    con = connect()
    uid, email = pick_user(con, args.email)
    current = _backup_latest(con, uid, email)
    ct = bytearray(bytes.fromhex(current["ciphertext"]))
    pos = min(args.byte, len(ct) - 1)
    before = ct[pos]
    ct[pos] ^= 0x01
    write_vault(con, uid, {**current, "ciphertext": ct.hex()})
    say(f"Byte {pos} del ciphertext de {email}: {before:02x} -> {ct[pos]:02x} (un solo bit).")
    say("Bloquea y desbloquea en la app: el tag Poly1305 no valida y la bóveda se rechaza.")
    say("Para volver a la normalidad: python -m demo restaurar")
    return 0


def cmd_restaurar(args) -> int:
    if not LATEST.exists():
        say("No hay nada que restaurar: el servidor ya sirve la última versión.")
        return 0
    con = connect()
    latest = json.loads(LATEST.read_text("utf-8"))
    uid, email = pick_user(con, latest["email"])
    write_vault(con, uid, latest)
    LATEST.unlink()
    say(f"El servidor vuelve a servir la bóveda v{latest['version']} de {email}, sin alterar.")
    return 0


# --------------------------------------------------------------------------- #
def main() -> int:
    for stream in (sys.stdout, sys.stderr):  # la consola de Windows puede no ser UTF-8
        try:
            stream.reconfigure(errors="replace")
        except AttributeError:
            pass
    parser = argparse.ArgumentParser(prog="python -m demo", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("servidor", help="levanta el servidor TLS de la demo")
    p.add_argument("--reset", action="store_true", help="borra la base de datos y los dispositivos")
    p.set_defaults(fn=cmd_servidor)

    p = sub.add_parser("app", help="abre el cliente como un dispositivo")
    p.add_argument("--dispositivo", default="laptop")
    p.add_argument("--pin-incorrecto", action="store_true")
    p.add_argument("--rapido", action="store_true")
    p.set_defaults(fn=cmd_app)

    p = sub.add_parser("bd", help="muestra lo que guarda el servidor")
    p.add_argument("--buscar", nargs="*", metavar="TEXTO")
    p.set_defaults(fn=cmd_bd)

    for name, fn, extra in (
        ("guardar-version", cmd_guardar_version, False),
        ("rollback", cmd_rollback, False),
        ("alterar", cmd_alterar, True),
        ("restaurar", cmd_restaurar, False),
    ):
        p = sub.add_parser(name)
        p.add_argument("--email")
        if extra:
            p.add_argument("--byte", type=int, default=100, help="posición del byte a alterar")
        p.set_defaults(fn=fn)

    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
