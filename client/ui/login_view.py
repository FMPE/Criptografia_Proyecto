"""Pantalla de acceso: desbloquear (con o sin passkey) o crear cuenta."""

from __future__ import annotations

from typing import Callable

import flet as ft

from client.crypto.generator import estimate_password_entropy
from client.crypto.keys import InvalidSecretKeyError
from client.net.api_client import ApiError, CertificatePinningError, NetworkError
from client.vault.manager import (
    MIN_MASTER_ENTROPY_BITS,
    MIN_MASTER_LENGTH,
    SecretKeyRequiredError,
    VaultError,
    VaultManager,
)

from .async_ops import Ui
from .dialogs import strength

UNLOCK, REGISTER = "unlock", "register"


class LoginView:
    def __init__(
        self, ui: Ui, manager: VaultManager, on_unlocked: Callable[[str | None], None]
    ) -> None:
        """`on_unlocked(secret_key)` recibe la Secret Key sólo tras un registro."""
        self.ui = ui
        self.manager = manager
        self.on_unlocked = on_unlocked

        self.mode = ft.SegmentedButton(
            segments=[
                ft.Segment(value=UNLOCK, label=ft.Text("Desbloquear"), icon=ft.Icon(ft.Icons.LOCK_OPEN)),
                ft.Segment(value=REGISTER, label=ft.Text("Crear cuenta"), icon=ft.Icon(ft.Icons.PERSON_ADD)),
            ],
            selected=[UNLOCK],
            on_change=self._switch_mode,
        )
        self.email = ft.TextField(label="Correo", prefix_icon=ft.Icons.EMAIL_OUTLINED, autofocus=True)
        self.password = ft.TextField(
            label="Contraseña maestra", password=True, can_reveal_password=True,
            prefix_icon=ft.Icons.PASSWORD, on_submit=self._submit, on_change=self._update_meter,
        )
        self.confirm = ft.TextField(
            label="Confirmar contraseña", password=True, can_reveal_password=True,
            prefix_icon=ft.Icons.PASSWORD, on_submit=self._submit, visible=False,
        )
        self.secret = ft.TextField(
            label="Secret Key", hint_text="PM1-XXXXX-XXXXX-…", prefix_icon=ft.Icons.VPN_KEY,
            helper="Dispositivo nuevo: transcríbela de tu kit de emergencia.",
            on_submit=self._submit, visible=False,
        )
        self.use_passkey = ft.Switch(label="Usar passkey (no envía AuthKey al servidor)", value=False)
        self.meter_bar = ft.ProgressBar(value=0, bar_height=6, border_radius=ft.BorderRadius.all(3), visible=False)
        self.meter_text = ft.Text("", size=12, visible=False)
        self.message = ft.Text("", color=ft.Colors.ERROR)
        self.submit = ft.FilledButton("Desbloquear", icon=ft.Icons.LOCK_OPEN, on_click=self._submit, height=44)

        card = ft.Card(
            elevation=4,
            content=ft.Container(
                width=460,
                padding=32,
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.SHIELD_OUTLINED, size=36, color=ft.Colors.PRIMARY),
                                ft.Text("Gestor de contraseñas", theme_style=ft.TextThemeStyle.HEADLINE_SMALL),
                            ]
                        ),
                        ft.Text(
                            "Cifrado extremo a extremo: el servidor sólo guarda un blob opaco.",
                            color=ft.Colors.ON_SURFACE_VARIANT, size=13,
                        ),
                        self.mode,
                        self.email,
                        self.password,
                        self.meter_bar,
                        self.meter_text,
                        self.confirm,
                        self.secret,
                        self.use_passkey,
                        self.message,
                        ft.Row([self.submit], alignment=ft.MainAxisAlignment.END),
                    ],
                    spacing=14,
                    tight=True,
                ),
            ),
        )
        self.control = ft.Container(content=card, alignment=ft.Alignment.CENTER, expand=True)

    # ------------------------------------------------------------------ #
    @property
    def registering(self) -> bool:
        return self.mode.selected == [REGISTER]

    def _switch_mode(self, _e) -> None:
        reg = self.registering
        self.confirm.visible = reg
        self.meter_bar.visible = self.meter_text.visible = reg
        self.use_passkey.visible = not reg
        self.secret.visible = False
        self.submit.content = "Crear cuenta" if reg else "Desbloquear"
        self.submit.icon = ft.Icons.PERSON_ADD if reg else ft.Icons.LOCK_OPEN
        self.message.value = ""
        self._update_meter(None, update=False)
        self.control.update()

    def _update_meter(self, _e, update: bool = True) -> None:
        if not self.registering:
            return
        pw = self.password.value or ""
        bits = estimate_password_entropy(pw)
        self.meter_bar.value, self.meter_bar.color, label = strength(bits)
        hint = ""
        if len(pw) < MIN_MASTER_LENGTH:
            hint = f" · mínimo {MIN_MASTER_LENGTH} caracteres"
        elif bits < MIN_MASTER_ENTROPY_BITS:
            hint = f" · mínimo {MIN_MASTER_ENTROPY_BITS:.0f} bits"
        self.meter_text.value = f"{label} · {bits:.0f} bits estimados{hint}"
        if update:
            self.control.update()

    def _fail(self, text: str) -> None:
        self.message.value = f"⚠ {text}"
        self.message.color = ft.Colors.ERROR
        self.control.update()

    async def _submit(self, _e) -> None:
        self.message.value = ""
        if self.registering:
            await self._register()
        else:
            await self._unlock()

    async def _unlock(self) -> None:
        try:
            await self.ui.run(
                self.manager.unlock,
                self.email.value or "",
                self.password.value or "",
                (self.secret.value or "").strip() or None,
                use_passkey=self.use_passkey.value,
                message="Derivando llaves con Argon2id (64 MiB)…",
            )
        except SecretKeyRequiredError:
            self.secret.visible = True
            self.message.value = "Este dispositivo no tiene tu Secret Key."
            self.message.color = ft.Colors.PRIMARY
            self.control.update()
            return
        except (VaultError, InvalidSecretKeyError, ValueError) as exc:
            return self._fail(str(exc))
        except CertificatePinningError as exc:
            return self._fail(str(exc))
        except (ApiError, NetworkError) as exc:
            return self._fail(f"Error del servidor: {exc}")
        finally:
            self.password.value = ""
            self.password.update()
        self.on_unlocked(None)

    async def _register(self) -> None:
        if (self.password.value or "") != (self.confirm.value or ""):
            return self._fail("Las contraseñas no coinciden")
        try:
            secret_key = await self.ui.run(
                self.manager.register,
                self.email.value or "",
                self.password.value or "",
                message="Generando Secret Key y derivando llaves…",
            )
        except (VaultError, ValueError) as exc:
            return self._fail(str(exc))
        except CertificatePinningError as exc:
            return self._fail(str(exc))
        except (ApiError, NetworkError) as exc:
            return self._fail(f"Error del servidor: {exc}")
        finally:
            self.password.value = self.confirm.value = ""
        self.on_unlocked(secret_key)
