"""Diálogos: desbloqueo/registro, kit de emergencia, generador y passkeys."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from client.crypto.generator import (
    GeneratorOptions,
    estimate_generator_entropy,
    estimate_password_entropy,
    generate_password,
)
from client.crypto.keys import InvalidSecretKeyError
from client.net.api_client import ApiError, NetworkError, RateLimitedError
from client.vault.manager import (
    SecretKeyRequiredError,
    VaultError,
    VaultManager,
)

from .util import busy


def _password_field() -> QLineEdit:
    f = QLineEdit()
    f.setEchoMode(QLineEdit.Password)
    return f


class LoginDialog(QDialog):
    """Pestañas: desbloquear (incluye dispositivo nuevo) y crear cuenta."""

    def __init__(self, manager: VaultManager, parent=None) -> None:
        super().__init__(parent)
        self.manager = manager
        self.new_secret_key: str | None = None
        self.setWindowTitle("Gestor de contraseñas")
        self.setMinimumWidth(460)

        tabs = QTabWidget()
        tabs.addTab(self._unlock_tab(), "Desbloquear")
        tabs.addTab(self._register_tab(), "Crear cuenta")
        layout = QVBoxLayout(self)
        layout.addWidget(tabs)

    # ---------------------------------------------------------------- #
    def _unlock_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        self.u_email = QLineEdit()
        self.u_password = _password_field()
        self.u_secret = QLineEdit()
        self.u_secret.setPlaceholderText("PM1-XXXXX-... (sólo en un dispositivo nuevo)")
        self.u_secret.setVisible(False)
        self.u_secret_label = QLabel("Secret Key")
        self.u_secret_label.setVisible(False)
        self.u_status = QLabel("")
        self.u_status.setWordWrap(True)
        btn = QPushButton("Desbloquear")
        btn.setDefault(True)
        btn.clicked.connect(self._do_unlock)
        self.u_password.returnPressed.connect(self._do_unlock)

        form.addRow("Correo", self.u_email)
        form.addRow("Contraseña maestra", self.u_password)
        self.u_passkey = QCheckBox("Iniciar sesión con passkey (no envía AuthKey al servidor)")
        self.u_passkey.setToolTip(
            "La bóveda se abre localmente y el servidor sólo recibe una firma Ed25519 "
            "sobre un challenge de un solo uso. Requiere un dispositivo ya usado."
        )

        form.addRow("Correo", self.u_email)
        form.addRow("Contraseña maestra", self.u_password)
        form.addRow(self.u_secret_label, self.u_secret)
        form.addRow(self.u_passkey)
        form.addRow(btn)
        form.addRow(self.u_status)
        return w

    def _do_unlock(self) -> None:
        secret = self.u_secret.text().strip() or None
        self.u_status.setText("Derivando llaves con Argon2id (64 MiB)…")
        try:
            with busy():
                self.manager.unlock(
                    self.u_email.text(),
                    self.u_password.text(),
                    secret,
                    use_passkey=self.u_passkey.isChecked(),
                )
        except SecretKeyRequiredError:
            self.u_secret.setVisible(True)
            self.u_secret_label.setVisible(True)
            self.u_status.setText(
                "Dispositivo nuevo: ingresa la Secret Key de tu kit de emergencia."
            )
            return
        except (VaultError, InvalidSecretKeyError, RateLimitedError, ValueError) as exc:
            self.u_status.setText(f"⚠ {exc}")
            return
        except (ApiError, NetworkError) as exc:
            self.u_status.setText(f"⚠ Error del servidor: {exc}")
            return
        finally:
            self.u_password.clear()
        self.accept()

    # ---------------------------------------------------------------- #
    def _register_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)
        self.r_email = QLineEdit()
        self.r_password = _password_field()
        self.r_confirm = _password_field()
        self.r_meter = QLabel("Entropía estimada: 0 bits")
        self.r_password.textChanged.connect(
            lambda t: self.r_meter.setText(
                f"Entropía estimada: {estimate_password_entropy(t):.0f} bits (mínimo 50)"
            )
        )
        self.r_status = QLabel("")
        self.r_status.setWordWrap(True)
        btn = QPushButton("Crear cuenta")
        btn.clicked.connect(self._do_register)

        form.addRow("Correo", self.r_email)
        form.addRow("Contraseña maestra", self.r_password)
        form.addRow("Confirmar", self.r_confirm)
        form.addRow(self.r_meter)
        form.addRow(btn)
        form.addRow(self.r_status)
        return w

    def _do_register(self) -> None:
        if self.r_password.text() != self.r_confirm.text():
            self.r_status.setText("⚠ Las contraseñas no coinciden")
            return
        self.r_status.setText("Generando Secret Key y derivando llaves…")
        try:
            with busy():
                self.new_secret_key = self.manager.register(
                    self.r_email.text(), self.r_password.text()
                )
        except (VaultError, ValueError) as exc:
            self.r_status.setText(f"⚠ {exc}")
            return
        except (ApiError, NetworkError) as exc:
            self.r_status.setText(f"⚠ Error del servidor: {exc}")
            return
        finally:
            self.r_password.clear()
            self.r_confirm.clear()
        self.accept()


class EmergencyKitDialog(QDialog):
    def __init__(self, email: str, secret_key: str, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Kit de emergencia")
        layout = QVBoxLayout(self)
        layout.addWidget(
            QLabel(
                "<b>Esta Secret Key se muestra una sola vez.</b><br>"
                "Guárdala fuera de la aplicación (impresa o en papel). Sin ella no podrás "
                "abrir tu bóveda en otro dispositivo, aunque recuerdes la contraseña maestra."
            )
        )
        layout.addWidget(QLabel(f"Cuenta: {email}"))
        key = QLabel(secret_key)
        key.setTextInteractionFlags(Qt.TextSelectableByMouse)
        font = QFont("Consolas")
        font.setPointSize(13)
        key.setFont(font)
        key.setWordWrap(True)
        layout.addWidget(key)

        confirm = QCheckBox("Confirmo que la guardé.")
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.button(QDialogButtonBox.Ok).setEnabled(False)
        confirm.toggled.connect(buttons.button(QDialogButtonBox.Ok).setEnabled)
        buttons.accepted.connect(self.accept)
        layout.addWidget(confirm)
        layout.addWidget(buttons)

    def reject(self) -> None:  # no se puede cerrar sin confirmar
        QMessageBox.information(self, "Kit de emergencia", "Confirma que guardaste la Secret Key.")


class GeneratorDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Generador de contraseñas")
        self.setMinimumWidth(420)
        layout = QVBoxLayout(self)

        self.output = QLineEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 12))
        layout.addWidget(self.output)

        form = QFormLayout()
        self.length = QSpinBox()
        self.length.setRange(8, 128)
        self.length.setValue(20)
        self.lower = QCheckBox("Minúsculas")
        self.upper = QCheckBox("Mayúsculas")
        self.digits = QCheckBox("Dígitos")
        self.symbols = QCheckBox("Símbolos")
        self.ambiguous = QCheckBox("Evitar caracteres ambiguos (I l 1 O 0)")
        for cb in (self.lower, self.upper, self.digits, self.symbols):
            cb.setChecked(True)
        form.addRow("Longitud", self.length)
        for cb in (self.lower, self.upper, self.digits, self.symbols, self.ambiguous):
            form.addRow(cb)
            cb.toggled.connect(self.regenerate)
        self.length.valueChanged.connect(self.regenerate)
        layout.addLayout(form)

        self.entropy = QLabel()
        layout.addWidget(self.entropy)
        layout.addWidget(QLabel("Fuente: CSPRNG del sistema operativo (secrets)"))

        row = QHBoxLayout()
        again = QPushButton("Regenerar")
        again.clicked.connect(self.regenerate)
        row.addWidget(again)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Usar")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        row.addWidget(buttons)
        layout.addLayout(row)
        self.regenerate()

    def options(self) -> GeneratorOptions:
        return GeneratorOptions(
            length=self.length.value(),
            lower=self.lower.isChecked(),
            upper=self.upper.isChecked(),
            digits=self.digits.isChecked(),
            symbols=self.symbols.isChecked(),
            avoid_ambiguous=self.ambiguous.isChecked(),
        )

    def regenerate(self) -> None:
        opts = self.options()
        try:
            self.output.setText(generate_password(opts))
            self.entropy.setText(f"Entropía estimada: {estimate_generator_entropy(opts):.0f} bits")
        except ValueError as exc:
            self.output.clear()
            self.entropy.setText(f"⚠ {exc}")

    def password(self) -> str:
        return self.output.text()


class PasskeysDialog(QDialog):
    """Lista, crea y revoca las passkeys Ed25519 de la cuenta."""

    def __init__(self, manager: VaultManager, parent=None) -> None:
        super().__init__(parent)
        self.manager = manager
        self.changed = False
        self.setWindowTitle("Passkeys")
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        layout.addWidget(
            QLabel(
                "Cada passkey es un par Ed25519. La llave privada se guarda cifrada "
                "dentro de tu bóveda; el servidor sólo conoce la llave pública."
            )
        )
        self.list = QListWidget()
        layout.addWidget(self.list)

        row = QHBoxLayout()
        create = QPushButton("Crear passkey")
        create.clicked.connect(self._create)
        revoke = QPushButton("Revocar")
        revoke.clicked.connect(self._revoke)
        test = QPushButton("Probar login")
        test.clicked.connect(self._test)
        close = QPushButton("Cerrar")
        close.clicked.connect(self.accept)
        for b in (create, revoke, test, close):
            row.addWidget(b)
        layout.addLayout(row)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.refresh()

    def refresh(self) -> None:
        self.list.clear()
        for pk in self.manager.vault.passkeys():
            fingerprint = pk.public_key[:16]
            item = QListWidgetItem(f"{pk.label}   ·   pk {fingerprint}…   ·   {pk.created_at}")
            item.setData(Qt.UserRole, pk.credential_id)
            self.list.addItem(item)

    def _run(self, action, ok_msg: str) -> None:
        try:
            with busy():
                action()
        except (VaultError, ApiError, NetworkError, ValueError) as exc:
            self.status.setText(f"⚠ {exc}")
            return
        self.status.setText(ok_msg)
        self.refresh()

    def _create(self) -> None:
        label, ok = QInputDialog.getText(self, "Nueva passkey", "Etiqueta (p. ej. «laptop»):")
        if ok and label.strip():
            self.changed = True
            self._run(lambda: self.manager.create_passkey(label.strip()[:64]),
                      "Passkey creada y guardada en la bóveda.")

    def _revoke(self) -> None:
        item = self.list.currentItem()
        if item is None:
            return
        if QMessageBox.question(self, "Revocar", "¿Revocar esta passkey?") != QMessageBox.Yes:
            return
        self.changed = True
        self._run(lambda: self.manager.revoke_passkey(item.data(Qt.UserRole)),
                  "Passkey revocada en el servidor y eliminada de la bóveda.")

    def _test(self) -> None:
        self._run(self.manager.login_with_passkey,
                  "Challenge firmado y verificado: el servidor emitió un token nuevo.")


def copy_to_clipboard(text: str) -> None:
    # TODO (P1): limpiar el portapapeles tras N segundos.
    QGuiApplication.clipboard().setText(text)
