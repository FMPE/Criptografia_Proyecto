"""Diálogos: confirmación, kit de emergencia, generador y passkeys."""

from __future__ import annotations

import asyncio
from typing import Callable

import flet as ft

from client.crypto.generator import (
    MAX_LENGTH,
    MIN_LENGTH,
    GeneratorOptions,
    estimate_generator_entropy,
    generate_password,
)
from client.net.api_client import ApiError, NetworkError
from client.vault.manager import VaultError, VaultManager

from .async_ops import Ui
from .clipboard import copy_to_clipboard

MONO = "Consolas"


def strength(bits: float) -> tuple[float, str, str]:
    """(fracción para la barra, color, etiqueta) a partir de bits de entropía."""
    if bits < 50:
        return min(bits / 128, 1.0), ft.Colors.RED, "Débil"
    if bits < 80:
        return bits / 128, ft.Colors.ORANGE, "Aceptable"
    return min(bits / 128, 1.0), ft.Colors.GREEN, "Fuerte"


# --------------------------------------------------------------------------- #
# Confirmación
# --------------------------------------------------------------------------- #
async def confirm(
    ui: Ui, title: str, message: str, ok_label: str = "Aceptar", destructive: bool = False
) -> bool:
    answer: asyncio.Future[bool] = asyncio.get_running_loop().create_future()

    def close(value: bool):
        def handler(_e):
            ui.page.pop_dialog()
            if not answer.done():
                answer.set_result(value)

        return handler

    ui.page.show_dialog(
        ft.AlertDialog(
            modal=True,
            title=ft.Text(title),
            content=ft.Text(message),
            actions=[
                ft.TextButton("Cancelar", on_click=close(False)),
                ft.FilledButton(
                    ok_label,
                    on_click=close(True),
                    bgcolor=ft.Colors.ERROR if destructive else None,
                    color=ft.Colors.ON_ERROR if destructive else None,
                ),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
    )
    return await answer


# --------------------------------------------------------------------------- #
# Kit de emergencia
# --------------------------------------------------------------------------- #
def show_emergency_kit(ui: Ui, email: str, secret_key: str) -> None:
    ok = ft.FilledButton("Listo", disabled=True, on_click=lambda _e: ui.page.pop_dialog())

    def toggle(e):
        ok.disabled = not e.control.value
        ok.update()

    async def copy(_e):
        await copy_to_clipboard(ui, secret_key, "Secret Key")

    ui.page.show_dialog(
        ft.AlertDialog(
            modal=True,  # no se cierra sin confirmar
            title=ft.Row([ft.Icon(ft.Icons.VPN_KEY), ft.Text("Kit de emergencia")]),
            content=ft.Column(
                [
                    ft.Text(
                        "Esta Secret Key se muestra una sola vez. Guárdala fuera de la "
                        "aplicación (impresa o en papel). Sin ella no podrás abrir tu bóveda "
                        "en otro dispositivo, aunque recuerdes la contraseña maestra.",
                    ),
                    ft.Text(f"Cuenta: {email}", color=ft.Colors.ON_SURFACE_VARIANT),
                    ft.Container(
                        content=ft.Text(secret_key, font_family=MONO, size=18, selectable=True),
                        padding=16,
                        border_radius=ft.BorderRadius.all(8),
                        bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
                    ),
                    ft.Row([ft.OutlinedButton("Copiar", icon=ft.Icons.CONTENT_COPY, on_click=copy)]),
                    ft.Checkbox(label="Confirmo que la guardé.", on_change=toggle),
                ],
                tight=True,
                spacing=12,
                width=520,
            ),
            actions=[ok],
        )
    )


# --------------------------------------------------------------------------- #
# Generador
# --------------------------------------------------------------------------- #
class GeneratorDialog:
    def __init__(self, ui: Ui, on_use: Callable[[str], None] | None = None) -> None:
        self.ui = ui
        self.on_use = on_use
        self.output = ft.Text("", font_family=MONO, size=18, selectable=True)
        self.length = ft.Slider(
            min=MIN_LENGTH, max=64, divisions=64 - MIN_LENGTH, value=20,
            label="{value}", on_change=self._regen,
        )
        self.length_text = ft.Text("Longitud: 20")
        self.lower = ft.Switch(label="Minúsculas", value=True, on_change=self._regen)
        self.upper = ft.Switch(label="Mayúsculas", value=True, on_change=self._regen)
        self.digits = ft.Switch(label="Dígitos", value=True, on_change=self._regen)
        self.symbols = ft.Switch(label="Símbolos", value=True, on_change=self._regen)
        self.ambiguous = ft.Switch(label="Evitar ambiguos (I l 1 O 0)", value=False, on_change=self._regen)
        self.bar = ft.ProgressBar(value=0, bar_height=8, border_radius=ft.BorderRadius.all(4))
        self.entropy = ft.Text("")

        actions = [
            ft.TextButton("Cerrar", on_click=lambda _e: ui.page.pop_dialog()),
            ft.OutlinedButton("Copiar", icon=ft.Icons.CONTENT_COPY, on_click=self._copy),
        ]
        if on_use:
            actions.append(ft.FilledButton("Usar", icon=ft.Icons.CHECK, on_click=self._use))

        self.dialog = ft.AlertDialog(
            title=ft.Row([ft.Icon(ft.Icons.AUTO_AWESOME), ft.Text("Generador de contraseñas")]),
            content=ft.Column(
                [
                    ft.Container(
                        content=ft.Row(
                            [self.output, ft.IconButton(ft.Icons.REFRESH, tooltip="Regenerar", on_click=self._regen)],
                            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        ),
                        padding=ft.Padding.symmetric(horizontal=16, vertical=8),
                        border_radius=ft.BorderRadius.all(8),
                        bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
                    ),
                    self.bar,
                    self.entropy,
                    self.length_text,
                    self.length,
                    ft.Row([self.lower, self.upper], wrap=True),
                    ft.Row([self.digits, self.symbols], wrap=True),
                    self.ambiguous,
                    ft.Text(
                        f"Fuente: CSPRNG del sistema operativo (secrets). Máximo {MAX_LENGTH} con la API.",
                        size=12, color=ft.Colors.ON_SURFACE_VARIANT,
                    ),
                ],
                tight=True,
                spacing=10,
                width=520,
            ),
            actions=actions,
        )
        self._regen(None, update=False)

    def options(self) -> GeneratorOptions:
        return GeneratorOptions(
            length=int(self.length.value),
            lower=self.lower.value,
            upper=self.upper.value,
            digits=self.digits.value,
            symbols=self.symbols.value,
            avoid_ambiguous=self.ambiguous.value,
        )

    def _regen(self, _e, update: bool = True) -> None:
        opts = self.options()
        self.length_text.value = f"Longitud: {opts.length}"
        try:
            self.output.value = generate_password(opts)
            bits = estimate_generator_entropy(opts)
            self.bar.value, self.bar.color, label = strength(bits)
            self.entropy.value = f"{label} · entropía estimada: {bits:.0f} bits"
        except ValueError as exc:
            self.output.value = ""
            self.bar.value = 0
            self.entropy.value = f"⚠ {exc}"
        if update:
            self.dialog.update()

    async def _copy(self, _e) -> None:
        await copy_to_clipboard(self.ui, self.output.value, "Contraseña")

    def _use(self, _e) -> None:
        if self.output.value and self.on_use:
            self.on_use(self.output.value)
        self.ui.page.pop_dialog()

    def show(self) -> None:
        self.ui.page.show_dialog(self.dialog)


# --------------------------------------------------------------------------- #
# Passkeys
# --------------------------------------------------------------------------- #
class PasskeysDialog:
    """Lista, crea, revoca y prueba las passkeys Ed25519 de la cuenta."""

    def __init__(self, ui: Ui, manager: VaultManager, on_change: Callable[[], None]) -> None:
        self.ui = ui
        self.manager = manager
        self.on_change = on_change
        self.list = ft.Column(spacing=0, tight=True)
        self.label = ft.TextField(label="Etiqueta de la nueva passkey", hint_text="p. ej. laptop", dense=True, expand=True, on_submit=self._create)
        self.status = ft.Text("", size=13)
        self.dialog = ft.AlertDialog(
            title=ft.Row([ft.Icon(ft.Icons.FINGERPRINT), ft.Text("Passkeys")]),
            content=ft.Column(
                [
                    ft.Text(
                        "Cada passkey es un par Ed25519. La llave privada se guarda cifrada "
                        "dentro de tu bóveda; el servidor sólo conoce la llave pública.",
                        size=13, color=ft.Colors.ON_SURFACE_VARIANT,
                    ),
                    self.list,
                    ft.Row([self.label, ft.FilledButton("Crear", icon=ft.Icons.ADD, on_click=self._create)]),
                    self.status,
                ],
                tight=True,
                spacing=12,
                width=540,
            ),
            actions=[
                ft.OutlinedButton("Probar login", icon=ft.Icons.KEY, on_click=self._test),
                ft.TextButton("Cerrar", on_click=lambda _e: ui.page.pop_dialog()),
            ],
        )
        self._refresh(update=False)

    def _refresh(self, update: bool = True) -> None:
        self.list.controls.clear()
        pks = self.manager.vault.passkeys()
        if not pks:
            self.list.controls.append(ft.Text("Todavía no hay passkeys.", italic=True))
        for pk in pks:
            self.list.controls.append(
                ft.ListTile(
                    leading=ft.Icon(ft.Icons.KEY),
                    title=ft.Text(pk.label),
                    subtitle=ft.Text(f"pk {pk.public_key[:16]}…  ·  {pk.created_at}", font_family=MONO, size=12),
                    trailing=ft.IconButton(
                        ft.Icons.DELETE_OUTLINE, tooltip="Revocar",
                        icon_color=ft.Colors.ERROR,
                        on_click=lambda _e, cid=pk.credential_id: self.ui.page.run_task(self._revoke, cid),
                    ),
                    dense=True,
                )
            )
        if update:
            self.dialog.update()

    async def _act(self, fn, *args, message: str, ok: str) -> None:
        try:
            await self.ui.run(fn, *args, message=message)
        except (VaultError, ApiError, NetworkError, ValueError) as exc:
            self.status.value = f"⚠ {exc}"
            self.status.color = ft.Colors.ERROR
        else:
            self.status.value = ok
            self.status.color = ft.Colors.GREEN
            self.on_change()
        self._refresh()

    async def _create(self, _e) -> None:
        label = (self.label.value or "").strip()[:64]
        if not label:
            self.status.value = "Escribe una etiqueta."
            self.dialog.update()
            return
        self.label.value = ""
        await self._act(self.manager.create_passkey, label,
                        message="Generando par Ed25519 y registrando la llave pública…",
                        ok="Passkey creada y guardada en la bóveda.")

    async def _revoke(self, credential_id: int) -> None:
        if not await confirm(self.ui, "Revocar passkey", "El servidor dejará de aceptarla. ¿Continuar?",
                             "Revocar", destructive=True):
            return
        await self._act(self.manager.revoke_passkey, credential_id,
                        message="Revocando…", ok="Passkey revocada en el servidor y eliminada de la bóveda.")

    async def _test(self, _e) -> None:
        await self._act(self.manager.login_with_passkey, message="Firmando challenge…",
                        ok="Challenge firmado y verificado: el servidor emitió un token nuevo.")

    def show(self) -> None:
        self.ui.page.show_dialog(self.dialog)
