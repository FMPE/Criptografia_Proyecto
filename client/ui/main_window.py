"""Ventana principal: lista de entradas, búsqueda, edición y sincronización."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from client.vault.manager import VaultError, VaultManager
from client.vault.models import Entry

from .dialogs import GeneratorDialog, copy_to_clipboard
from .util import busy

ALL_TAGS = "Todas las etiquetas"


class MainWindow(QMainWindow):
    locked = Signal()

    def __init__(self, manager: VaultManager) -> None:
        super().__init__()
        self.manager = manager
        self.current_id: str | None = None
        self.dirty = False
        self.setWindowTitle(f"Mi bóveda — {manager.email}")
        self.resize(900, 560)

        # ---- Panel izquierdo: búsqueda + lista ---------------------- #
        self.search = QLineEdit()
        self.search.setPlaceholderText("Buscar…")
        self.search.textChanged.connect(self.refresh_list)
        self.tag_filter = QComboBox()
        self.tag_filter.currentTextChanged.connect(self.refresh_list)
        self.list = QListWidget()
        self.list.currentItemChanged.connect(self._on_select)
        new_btn = QPushButton("+ Nueva")
        new_btn.clicked.connect(self.new_entry)

        left = QWidget()
        lv = QVBoxLayout(left)
        lv.addWidget(self.search)
        lv.addWidget(self.tag_filter)
        lv.addWidget(self.list)
        lv.addWidget(new_btn)

        # ---- Panel derecho: detalle --------------------------------- #
        self.f_service = QLineEdit()
        self.f_username = QLineEdit()
        self.f_password = QLineEdit()
        self.f_password.setEchoMode(QLineEdit.Password)
        self.f_url = QLineEdit()
        self.f_tags = QLineEdit()
        self.f_tags.setPlaceholderText("trabajo, personal, …")
        self.f_notes = QPlainTextEdit()

        show_btn = QPushButton("Ver")
        show_btn.setCheckable(True)
        show_btn.toggled.connect(
            lambda on: self.f_password.setEchoMode(QLineEdit.Normal if on else QLineEdit.Password)
        )
        gen_btn = QPushButton("Generar")
        gen_btn.clicked.connect(self.open_generator)
        copy_btn = QPushButton("Copiar")
        copy_btn.clicked.connect(lambda: self._copy(self.f_password.text()))
        pw_row = QHBoxLayout()
        for w in (self.f_password, show_btn, gen_btn, copy_btn):
            pw_row.addWidget(w)

        form = QFormLayout()
        form.addRow("Servicio", self.f_service)
        form.addRow("Usuario", self.f_username)
        form.addRow("Contraseña", pw_row)
        form.addRow("URL", self.f_url)
        form.addRow("Etiquetas", self.f_tags)
        form.addRow("Notas", self.f_notes)

        self.save_btn = QPushButton("Guardar entrada")
        self.save_btn.clicked.connect(self.save_entry)
        dup_btn = QPushButton("Duplicar")
        dup_btn.clicked.connect(self.duplicate_entry)
        del_btn = QPushButton("Eliminar")
        del_btn.clicked.connect(self.delete_entry)
        actions = QHBoxLayout()
        for w in (self.save_btn, dup_btn, del_btn):
            actions.addWidget(w)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.addLayout(form)
        rv.addLayout(actions)

        splitter = QSplitter()
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([300, 600])
        self.setCentralWidget(splitter)

        # ---- Barra de herramientas ---------------------------------- #
        tb = self.addToolBar("Bóveda")
        tb.addAction("Sincronizar (subir)", self.sync_push)
        tb.addAction("Recargar del servidor", self.sync_pull)
        tb.addAction("Bloquear", self.lock)

        self.refresh_list()
        self.clear_form()
        self.update_status()

    # ---------------------------------------------------------------- #
    @property
    def vault(self):
        return self.manager.vault

    def update_status(self, extra: str = "") -> None:
        mode = "en línea" if self.manager.online else "SIN CONEXIÓN (sólo lectura)"
        pending = " · cambios sin subir" if self.dirty else " · sincronizado"
        self.statusBar().showMessage(f"v{self.manager.version} · {mode}{pending} {extra}")

    def refresh_list(self) -> None:
        tag = self.tag_filter.currentText()
        tags = self.vault.tags()
        self.tag_filter.blockSignals(True)
        self.tag_filter.clear()
        self.tag_filter.addItems([ALL_TAGS, *tags])
        if tag in tags:
            self.tag_filter.setCurrentText(tag)
        self.tag_filter.blockSignals(False)

        selected = None if self.tag_filter.currentText() == ALL_TAGS else self.tag_filter.currentText()
        self.list.blockSignals(True)
        self.list.clear()
        for e in self.vault.search(self.search.text(), selected):
            item = QListWidgetItem(f"{e.service}\n  {e.username}")
            item.setData(Qt.UserRole, e.id)
            self.list.addItem(item)
            if e.id == self.current_id:
                self.list.setCurrentItem(item)
        self.list.blockSignals(False)

    def _on_select(self, item: QListWidgetItem | None) -> None:
        if item is None:
            return
        self.current_id = item.data(Qt.UserRole)
        self.fill_form(self.vault.get(self.current_id))

    def fill_form(self, e: Entry) -> None:
        self.f_service.setText(e.service)
        self.f_username.setText(e.username)
        self.f_password.setText(e.password)
        self.f_url.setText(e.url)
        self.f_tags.setText(", ".join(e.tags))
        self.f_notes.setPlainText(e.notes)

    def clear_form(self) -> None:
        self.current_id = None
        for f in (self.f_service, self.f_username, self.f_password, self.f_url, self.f_tags):
            f.clear()
        self.f_notes.clear()
        self.list.clearSelection()

    def _form_values(self) -> dict:
        return {
            "service": self.f_service.text().strip(),
            "username": self.f_username.text(),
            "password": self.f_password.text(),
            "url": self.f_url.text().strip(),
            "notes": self.f_notes.toPlainText(),
            "tags": [t.strip() for t in self.f_tags.text().split(",") if t.strip()],
        }

    # ---------------------------------------------------------------- #
    def new_entry(self) -> None:
        self.clear_form()
        self.f_service.setFocus()

    def save_entry(self) -> None:
        values = self._form_values()
        try:
            if self.current_id is None:
                self.current_id = self.vault.add(Entry(**values)).id
            else:
                self.vault.update(self.current_id, **values)
        except ValueError as exc:
            QMessageBox.warning(self, "Entrada", str(exc))
            return
        self.dirty = True
        self.refresh_list()
        self.sync_push()

    def duplicate_entry(self) -> None:
        if self.current_id:
            self.current_id = self.vault.duplicate(self.current_id).id
            self.dirty = True
            self.refresh_list()
            self.fill_form(self.vault.get(self.current_id))
            self.sync_push()

    def delete_entry(self) -> None:
        if not self.current_id:
            return
        e = self.vault.get(self.current_id)
        if QMessageBox.question(self, "Eliminar", f"¿Eliminar «{e.service}»?") != QMessageBox.Yes:
            return
        self.vault.delete(self.current_id)
        self.dirty = True
        self.clear_form()
        self.refresh_list()
        self.sync_push()

    def open_generator(self) -> None:
        dlg = GeneratorDialog(self)
        if dlg.exec():
            self.f_password.setText(dlg.password())

    def _copy(self, text: str) -> None:
        if text:
            copy_to_clipboard(text)
            self.update_status("· copiado al portapapeles")

    # ---------------------------------------------------------------- #
    def sync_push(self) -> None:
        if not self.dirty:
            return
        try:
            with busy():
                self.manager.save()
        except VaultError as exc:
            QMessageBox.warning(self, "Sincronización", str(exc))
            self.update_status()
            return
        self.dirty = False
        self.update_status()

    def sync_pull(self) -> None:
        if self.dirty and QMessageBox.question(
            self, "Recargar", "Hay cambios sin subir que se perderán. ¿Continuar?"
        ) != QMessageBox.Yes:
            return
        try:
            with busy():
                self.manager.pull()
        except VaultError as exc:
            QMessageBox.warning(self, "Sincronización", str(exc))
            return
        self.dirty = False
        self.clear_form()
        self.refresh_list()
        self.update_status()

    def closeEvent(self, event) -> None:
        # Cerrar la ventana (sin pasar por "Bloquear") también bloquea y sale.
        if self.manager.is_unlocked:
            if self.dirty and QMessageBox.question(
                self, "Salir", "Hay cambios sin subir que se perderán. ¿Salir igual?"
            ) != QMessageBox.Yes:
                event.ignore()
                return
            self.manager.lock()
            QApplication.quit()
        event.accept()

    def lock(self) -> None:
        self.clear_form()
        self.list.clear()
        self.manager.lock()
        self.locked.emit()
        self.close()
