"""Vista principal: lista de entradas, búsqueda por texto y etiquetas, detalle y sincronización."""

from __future__ import annotations

from typing import Callable

import flet as ft

from client.net.api_client import ApiError, NetworkError
from client.vault.manager import VaultError, VaultManager
from client.vault.models import Entry

from .account_dialogs import ChangePasswordDialog, ExportDialog, PreferencesDialog, pick_and_import
from .async_ops import Ui
from .clipboard import copy_to_clipboard
from .dialogs import GeneratorDialog, PasskeysDialog, confirm


class VaultView:
    def __init__(self, ui: Ui, manager: VaultManager, on_locked: Callable[[], None]) -> None:
        self.ui = ui
        self.manager = manager
        self.on_locked = on_locked
        self.current_id: str | None = None
        self.tag: str | None = None
        self.dirty = False  # cambios en la bóveda que no se pudieron subir

        # ---- Encabezado ------------------------------------------------- #
        self.status = ft.Text("", size=12)
        self.status_icon = ft.Icon(ft.Icons.CLOUD_DONE, size=16)
        header = ft.Container(
            padding=ft.Padding.symmetric(horizontal=20, vertical=10),
            bgcolor=ft.Colors.SURFACE_CONTAINER_LOW,
            content=ft.Row(
                [
                    ft.Icon(ft.Icons.SHIELD_OUTLINED, color=ft.Colors.PRIMARY, size=28),
                    ft.Column(
                        [
                            ft.Text("Mi bóveda", theme_style=ft.TextThemeStyle.TITLE_LARGE),
                            ft.Text(manager.email or "", size=12, color=ft.Colors.ON_SURFACE_VARIANT),
                        ],
                        spacing=0,
                        tight=True,
                    ),
                    ft.Container(expand=True),
                    ft.Container(
                        content=ft.Row([self.status_icon, self.status], spacing=6, tight=True),
                        padding=ft.Padding.symmetric(horizontal=12, vertical=6),
                        border_radius=ft.BorderRadius.all(16),
                        bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
                    ),
                    ft.IconButton(ft.Icons.CLOUD_UPLOAD, tooltip="Subir cambios", on_click=self._push),
                    ft.IconButton(ft.Icons.REFRESH, tooltip="Recargar del servidor", on_click=self._pull),
                    ft.IconButton(ft.Icons.AUTO_AWESOME, tooltip="Generador", on_click=self._open_generator),
                    ft.IconButton(ft.Icons.FINGERPRINT, tooltip="Passkeys", on_click=self._open_passkeys),
                    ft.PopupMenuButton(
                        icon=ft.Icons.MANAGE_ACCOUNTS,
                        tooltip="Cuenta y seguridad",
                        items=[
                            ft.PopupMenuItem(content="Cambiar contraseña maestra", icon=ft.Icons.PASSWORD,
                                             on_click=self._open_change_password),
                            ft.PopupMenuItem(content="Exportar respaldo cifrado", icon=ft.Icons.FILE_UPLOAD_OUTLINED,
                                             on_click=self._open_export),
                            ft.PopupMenuItem(content="Importar respaldo cifrado", icon=ft.Icons.FILE_DOWNLOAD_OUTLINED,
                                             on_click=self._open_import),
                            ft.PopupMenuItem(content="Bloqueo y portapapeles", icon=ft.Icons.TIMER_OUTLINED,
                                             on_click=self._open_preferences),
                        ],
                    ),
                    ft.IconButton(ft.Icons.LOCK, tooltip="Bloquear", on_click=self._lock),
                ],
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
        )

        # ---- Panel izquierdo -------------------------------------------- #
        self.search = ft.TextField(
            hint_text="Buscar…", prefix_icon=ft.Icons.SEARCH, dense=True,
            border_radius=ft.BorderRadius.all(24), on_change=lambda _e: self.refresh(),
        )
        self.tags_row = ft.Row(wrap=True, spacing=6, run_spacing=6)
        self.entries = ft.ListView(expand=True, spacing=2)
        left = ft.Container(
            width=320,
            padding=16,
            content=ft.Column(
                [
                    self.search,
                    self.tags_row,
                    ft.FilledButton("Nueva entrada", icon=ft.Icons.ADD, on_click=self._new),
                    self.entries,
                ],
                spacing=12,
                expand=True,
            ),
        )

        # ---- Panel derecho: detalle ------------------------------------- #
        self.title = ft.Text("Nueva entrada", theme_style=ft.TextThemeStyle.HEADLINE_SMALL)
        self.meta = ft.Text("", size=12, color=ft.Colors.ON_SURFACE_VARIANT)
        self.f_service = ft.TextField(label="Servicio", prefix_icon=ft.Icons.LANGUAGE)
        self.f_username = ft.TextField(label="Usuario", prefix_icon=ft.Icons.PERSON_OUTLINE, expand=True)
        self.f_password = ft.TextField(
            label="Contraseña", prefix_icon=ft.Icons.PASSWORD, password=True,
            can_reveal_password=True, expand=True,
        )
        self.f_url = ft.TextField(label="URL", prefix_icon=ft.Icons.LINK)
        self.f_tags = ft.TextField(label="Etiquetas", hint_text="trabajo, personal, …", prefix_icon=ft.Icons.LABEL_OUTLINE)
        self.f_notes = ft.TextField(label="Notas", multiline=True, min_lines=3, max_lines=6, prefix_icon=ft.Icons.NOTES)
        self.btn_duplicate = ft.OutlinedButton("Duplicar", icon=ft.Icons.COPY_ALL, on_click=self._duplicate)
        self.btn_delete = ft.TextButton("Eliminar", icon=ft.Icons.DELETE_OUTLINE, on_click=self._delete,
                                        style=ft.ButtonStyle(color=ft.Colors.ERROR))

        detail = ft.Container(
            expand=True,
            padding=ft.Padding.symmetric(horizontal=28, vertical=20),
            content=ft.Column(
                [
                    self.title,
                    self.meta,
                    self.f_service,
                    ft.Row(
                        [self.f_username,
                         ft.IconButton(ft.Icons.CONTENT_COPY, tooltip="Copiar usuario", on_click=self._copy_username)]
                    ),
                    ft.Row(
                        [
                            self.f_password,
                            ft.IconButton(ft.Icons.AUTO_AWESOME, tooltip="Generar", on_click=self._generate_for_entry),
                            ft.IconButton(ft.Icons.CONTENT_COPY, tooltip="Copiar contraseña", on_click=self._copy_password),
                        ]
                    ),
                    self.f_url,
                    self.f_tags,
                    self.f_notes,
                    ft.Row(
                        [
                            self.btn_delete,
                            ft.Container(expand=True),
                            self.btn_duplicate,
                            ft.FilledButton("Guardar", icon=ft.Icons.SAVE, on_click=self._save),
                        ]
                    ),
                ],
                spacing=14,
                scroll=ft.ScrollMode.AUTO,
                expand=True,
            ),
        )

        self.control = ft.Column(
            [
                header,
                ft.Row(
                    [left, ft.VerticalDivider(width=1), detail],
                    expand=True,
                    vertical_alignment=ft.CrossAxisAlignment.STRETCH,
                ),
            ],
            spacing=0,
            expand=True,
        )
        self._clear_form()
        self.refresh(update=False)

    # ------------------------------------------------------------------ #
    # Estado y lista
    # ------------------------------------------------------------------ #
    @property
    def vault(self):
        return self.manager.vault

    def _update_status(self) -> None:
        m = self.manager
        if not m.online:
            icon, text = ft.Icons.CLOUD_OFF, f"v{m.version} · sin conexión (sólo lectura)"
        elif self.dirty:
            icon, text = ft.Icons.CLOUD_UPLOAD, f"v{m.version} · cambios sin subir"
        else:
            icon, text = ft.Icons.CLOUD_DONE, f"v{m.version} · sincronizado"
        if m.auth_method:
            text += f" · sesión por {m.auth_method}"
        self.status_icon.name = icon
        self.status_icon.color = ft.Colors.ORANGE if (self.dirty or not m.online) else ft.Colors.GREEN
        self.status.value = text

    def _tag_chip(self, label: str, tag: str | None) -> ft.Chip:
        def select(_e):
            self.tag = None if self.tag == tag else tag
            self.refresh()

        return ft.Chip(label=ft.Text(label), selected=self.tag == tag, on_select=select)

    def refresh(self, update: bool = True) -> None:
        tags = self.vault.tags()
        if self.tag not in tags:
            self.tag = None
        self.tags_row.controls = [self._tag_chip("Todas", None)] + [self._tag_chip(t, t) for t in tags]

        results = self.vault.search(self.search.value or "", self.tag)
        self.entries.controls.clear()
        for e in results:
            self.entries.controls.append(
                ft.ListTile(
                    leading=ft.CircleAvatar(
                        content=ft.Text((e.service[:1] or "?").upper()),
                        bgcolor=ft.Colors.PRIMARY_CONTAINER,
                    ),
                    title=ft.Text(e.service),
                    subtitle=ft.Text(e.username or "—", size=12),
                    selected=e.id == self.current_id,
                    on_click=lambda _ev, eid=e.id: self._select(eid),
                    dense=True,
                )
            )
        if not results:
            empty = "Tu bóveda está vacía" if len(self.vault) == 0 else "Sin resultados"
            self.entries.controls.append(
                ft.Container(
                    padding=24,
                    alignment=ft.Alignment.CENTER,
                    content=ft.Column(
                        [ft.Icon(ft.Icons.INBOX, size=40, color=ft.Colors.ON_SURFACE_VARIANT),
                         ft.Text(empty, color=ft.Colors.ON_SURFACE_VARIANT)],
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        tight=True,
                    ),
                )
            )
        self._update_status()
        if update:
            self.control.update()

    # ------------------------------------------------------------------ #
    # Formulario
    # ------------------------------------------------------------------ #
    def _fill(self, e: Entry) -> None:
        self.title.value = e.service
        self.meta.value = f"Última modificación: {e.updated_at}"
        self.f_service.value = e.service
        self.f_username.value = e.username
        self.f_password.value = e.password
        self.f_url.value = e.url
        self.f_tags.value = ", ".join(e.tags)
        self.f_notes.value = e.notes
        self.btn_duplicate.disabled = self.btn_delete.disabled = False

    def _clear_form(self) -> None:
        self.current_id = None
        self.title.value = "Nueva entrada"
        self.meta.value = ""
        for f in (self.f_service, self.f_username, self.f_password, self.f_url, self.f_tags, self.f_notes):
            f.value = ""
        self.btn_duplicate.disabled = self.btn_delete.disabled = True

    def _values(self) -> dict:
        return {
            "service": (self.f_service.value or "").strip(),
            "username": self.f_username.value or "",
            "password": self.f_password.value or "",
            "url": (self.f_url.value or "").strip(),
            "notes": self.f_notes.value or "",
            "tags": [t.strip() for t in (self.f_tags.value or "").split(",") if t.strip()],
        }

    def _select(self, entry_id: str) -> None:
        self.current_id = entry_id
        self._fill(self.vault.get(entry_id))
        self.refresh()

    def _new(self, _e) -> None:
        self._clear_form()
        self.refresh()
        self.f_service.focus()

    # ------------------------------------------------------------------ #
    # Acciones sobre entradas (cada cambio se sube al servidor)
    # ------------------------------------------------------------------ #
    async def _save(self, _e) -> None:
        values = self._values()
        try:
            if self.current_id is None:
                self.current_id = self.vault.add(Entry(**values)).id
            else:
                self.vault.update(self.current_id, **values)
        except ValueError as exc:
            self.ui.notify(str(exc), error=True)
            return
        self._fill(self.vault.get(self.current_id))
        self.dirty = True
        await self._sync("Entrada guardada")

    async def _duplicate(self, _e) -> None:
        if not self.current_id:
            return
        self.current_id = self.vault.duplicate(self.current_id).id
        self._fill(self.vault.get(self.current_id))
        self.dirty = True
        await self._sync("Entrada duplicada")

    async def _delete(self, _e) -> None:
        if not self.current_id:
            return
        service = self.vault.get(self.current_id).service
        if not await confirm(self.ui, "Eliminar entrada", f"¿Eliminar «{service}»?", "Eliminar", destructive=True):
            return
        self.vault.delete(self.current_id)
        self._clear_form()
        self.dirty = True
        await self._sync("Entrada eliminada")

    async def _copy_username(self, _e) -> None:
        await copy_to_clipboard(self.ui, self.f_username.value or "", "Usuario")

    async def _copy_password(self, _e) -> None:
        await copy_to_clipboard(self.ui, self.f_password.value or "", "Contraseña")

    def _generate_for_entry(self, _e) -> None:
        def use(pw: str) -> None:
            self.f_password.value = pw
            self.f_password.update()

        GeneratorDialog(self.ui, on_use=use).show()

    def _open_generator(self, _e) -> None:
        GeneratorDialog(self.ui).show()

    def _open_passkeys(self, _e) -> None:
        def changed() -> None:
            # Crear/revocar sube la bóveda entera: si funcionó, no quedan cambios pendientes.
            self.dirty = False
            self.refresh()

        PasskeysDialog(self.ui, self.manager, on_change=changed).show()

    def _open_change_password(self, _e) -> None:
        if not self.manager.online:
            self.ui.notify("Sin conexión: no se puede cambiar la contraseña", error=True)
            return
        ChangePasswordDialog(self.ui, self.manager, on_done=self.refresh).show()

    def _open_export(self, _e) -> None:
        ExportDialog(self.ui, self.manager).show()

    async def _open_import(self, _e) -> None:
        def done(added: int) -> None:
            # import_backup sólo llama a save() si agregó entradas: con 0, los cambios
            # pendientes que hubiera siguen sin subir.
            if added:
                self.dirty = False
            self.refresh()

        await pick_and_import(self.ui, self.manager, done)

    def _open_preferences(self, _e) -> None:
        PreferencesDialog(self.ui, self.manager.home).show()

    # ------------------------------------------------------------------ #
    # Sincronización
    # ------------------------------------------------------------------ #
    async def _sync(self, ok_message: str) -> None:
        try:
            await self.ui.run(self.manager.save, message="Cifrando y subiendo la bóveda…")
        except (VaultError, ApiError, NetworkError) as exc:
            self.ui.notify(str(exc), error=True)
        else:
            self.dirty = False
            self.ui.notify(ok_message)
        self.refresh()

    async def _push(self, _e) -> None:
        if not self.dirty:
            self.ui.notify("No hay cambios pendientes")
            return
        await self._sync("Bóveda sincronizada")

    async def _pull(self, _e) -> None:
        if self.dirty and not await confirm(
            self.ui, "Recargar", "Hay cambios sin subir que se perderán. ¿Continuar?", "Recargar", destructive=True
        ):
            return
        try:
            await self.ui.run(self.manager.pull, message="Descargando y verificando la bóveda…")
        except (VaultError, ApiError, NetworkError) as exc:
            self.ui.notify(str(exc), error=True)
            return
        self.dirty = False
        self._clear_form()
        self.refresh()
        self.ui.notify(f"Bóveda recargada (v{self.manager.version})")

    async def _lock(self, _e) -> None:
        if self.dirty and not await confirm(
            self.ui, "Bloquear", "Hay cambios sin subir que se perderán. ¿Bloquear igual?", "Bloquear", destructive=True
        ):
            return
        self._clear_form()
        await self.ui.clipboard_guard.clear_if_ours()
        self.manager.lock()
        self.on_locked()
