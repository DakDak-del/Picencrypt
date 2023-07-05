import os
from enum import Enum
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QComboBox, QLineEdit, QVBoxLayout, QWidget, QFileDialog, QMessageBox, QStyleFactory, QPlainTextEdit, QSizePolicy, QHBoxLayout, QCheckBox
from PyQt5.QtGui import QPalette, QColor, QTextOption, QIcon
from PyQt5.QtCore import Qt, QMimeData, QTimer
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.PublicKey import RSA
from stegano import lsb
import time

class EncryptionMethods(Enum):
    AES = "AES"
    RSA = "RSA"

class PETGui(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Picencrpyt")
        self.setGeometry(100, 100, 400, 250)

        self.file_path_label = QLabel("No file currently selected")
        self.file_path_label.setAlignment(Qt.AlignCenter)

        self.file_select_button = QPushButton("Select a File or Drag and Drop photo into window")
        self.file_select_button.clicked.connect(self.select_file)

        self.encryption_method_label = QLabel("Encryption Method:")
        self.encryption_method_combo = QComboBox()
        self.encryption_method_combo.addItem(EncryptionMethods.AES.value)
        self.encryption_method_combo.addItem(EncryptionMethods.RSA.value)

        self.encryption_key_label = QLabel("Encryption Key:")
        self.encryption_key_input = QLineEdit()
        self.encryption_key_input.setReadOnly(True)

        self.copy_key_button = QPushButton("Copy")
        self.copy_key_button.clicked.connect(self.copy_encryption_key)

        self.clear_key_button = QPushButton("Clear")
        self.clear_key_button.clicked.connect(self.clear_encryption_key)

        self.decryption_key_label = QLabel("Decryption Key:")
        self.decryption_key_input = QLineEdit()

        self.paste_key_button = QPushButton("Paste")
        self.paste_key_button.clicked.connect(self.paste_decryption_key)

        self.clear_key_button_2 = QPushButton("Clear")
        self.clear_key_button_2.clicked.connect(self.clear_decryption_key)

        self.data_to_embed_label = QLabel("Data to Embed:")
        self.data_to_embed_input = QPlainTextEdit()
        self.data_to_embed_input.setPlaceholderText("Enter data to embed")
        self.data_to_embed_input.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.data_to_embed_input.setWordWrapMode(QTextOption.WrapAnywhere)
        self.data_to_embed_input.setMaximumHeight(100)

        self.decrypted_data_label = QLabel("Decrypted Data:")
        self.decrypted_data_output = QPlainTextEdit()
        self.decrypted_data_output.setReadOnly(True)
        self.decrypted_data_output.setPlaceholderText("Decrypted data will appear here")
        self.decrypted_data_output.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.decrypted_data_output.setWordWrapMode(QTextOption.WrapAnywhere)
        self.decrypted_data_output.setMaximumHeight(100)

        self.encrypt_button = QPushButton("Encrypt Data")
        self.encrypt_button.clicked.connect(self.encrypt_data)

        self.decrypt_button = QPushButton("Decrypt Data")
        self.decrypt_button.clicked.connect(self.decrypt_data)

        self.hide_keys_button = QCheckBox("Hide Keys")
        self.hide_keys_button.setChecked(False)
        self.hide_keys_button.toggled.connect(self.toggle_key_visibility)


        self.dark_light_mode_button = QPushButton("Dark Mode")
        self.dark_light_mode_button.clicked.connect(self.toggle_dark_light_mode)

        self.set_dark_mode()

        layout = QVBoxLayout()
        layout.addWidget(self.file_path_label)
        layout.addWidget(self.file_select_button)

        encryption_layout = QHBoxLayout()
        encryption_layout.addWidget(self.encryption_method_label)
        encryption_layout.addWidget(self.encryption_method_combo)
        layout.addLayout(encryption_layout)

        key_layout = QHBoxLayout()
        key_layout.addWidget(self.encryption_key_label)
        key_layout.addWidget(self.encryption_key_input)
        key_layout.addWidget(self.copy_key_button)
        key_layout.addWidget(self.clear_key_button)
        layout.addLayout(key_layout)

        decryption_layout = QHBoxLayout()
        decryption_layout.addWidget(self.decryption_key_label)
        decryption_layout.addWidget(self.decryption_key_input)
        decryption_layout.addWidget(self.paste_key_button)
        decryption_layout.addWidget(self.clear_key_button_2)
        layout.addLayout(decryption_layout)

        layout.addWidget(self.data_to_embed_label)
        layout.addWidget(self.data_to_embed_input)
        layout.addWidget(self.decrypted_data_label)
        layout.addWidget(self.decrypted_data_output)

        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.encrypt_button)
        buttons_layout.addWidget(self.decrypt_button)
        layout.addLayout(buttons_layout)

        options_layout = QHBoxLayout()
        options_layout.addWidget(self.hide_keys_button)
        options_layout.addWidget(self.dark_light_mode_button)
        layout.addLayout(options_layout)

        widget = QWidget()
        widget.setLayout(layout)
        self.setCentralWidget(widget)

        # Set the application style to 'Fusion' (default dark mode)
        QApplication.setStyle(QStyleFactory.create("Fusion"))

        # Enable drag and drop events
        self.setAcceptDrops(True)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a File or Drag and Drop file into window", filter="Images (*.png)")
        if file_path:
            self.file_path_label.setText(file_path)

    def encrypt_data(self):
        file_path = self.file_path_label.text()
        encryption_method = self.encryption_method_combo.currentText()
        data = self.data_to_embed_input.toPlainText()

        if not file_path:
            QMessageBox.critical(self, "File Error", "Please select a file.")
            return

        if not data:
            QMessageBox.critical(self, "Data Error", "Please enter data to embed.")
            return

        if encryption_method == EncryptionMethods.AES.value:
            encryption_key = self.encryption_key_input.text()

            if not encryption_key:
                encryption_key = self.generate_encryption_key()
                self.encryption_key_input.setText(encryption_key)

            key = self.hex_key_to_bytes(encryption_key)

            try:
                encrypted_data = self.encrypt_data_aes(data, key)
                secret_image = lsb.hide(file_path, encrypted_data.hex())
                save_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", filter="Images (*.png)")
                if save_path:
                    secret_image.save(save_path)
                    QMessageBox.information(self, "Success", "File saved successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Encryption Error", f"An error occurred during encryption:\n{str(e)}")
        elif encryption_method == EncryptionMethods.RSA.value:
            try:
                public_key = RSA.generate(2048)
                private_key = public_key.export_key()
                encryption_key = private_key.decode('utf-8')
                self.encryption_key_input.setText(encryption_key)

                encrypted_data = self.encrypt_data_rsa(data, public_key)
                secret_image = lsb.hide(file_path, encrypted_data.hex())
                save_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", filter="Images (*.png)")
                if save_path:
                    secret_image.save(save_path)
                    QMessageBox.information(self, "Success", "File saved successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Encryption Error", f"An error occurred during encryption:\n{str(e)}")
        else:
            QMessageBox.warning(self, "Unsupported Method", "The selected encryption method is not supported yet.")

    def decrypt_data(self):
        file_path = self.file_path_label.text()
        encryption_method = self.encryption_method_combo.currentText()

        if not file_path:
            QMessageBox.critical(self, "File Error", "Please select a file.")
            return

        if encryption_method == EncryptionMethods.AES.value:
            decryption_key = self.decryption_key_input.text()

            if not decryption_key:
                QMessageBox.critical(self, "Key Error", "Please enter a decryption key.")
                return

            key = self.hex_key_to_bytes(decryption_key)

            try:
                encrypted_data_hex = lsb.reveal(file_path)
                decrypted_data = self.decrypt_data_aes(bytes.fromhex(encrypted_data_hex), key)
                self.decrypted_data_output.setPlainText(decrypted_data)
            except Exception as e:
                QMessageBox.critical(self, "Decryption Error", f"An error occurred during decryption:\n{str(e)}")
        elif encryption_method == EncryptionMethods.RSA.value:
            decryption_key = self.decryption_key_input.text()

            if not decryption_key:
                QMessageBox.critical(self, "Key Error", "Please enter a decryption key.")
                return

            try:
                private_key = RSA.import_key(decryption_key)
                decrypted_data = self.decrypt_data_rsa(file_path, private_key)
                self.decrypted_data_output.setPlainText(decrypted_data)
            except Exception as e:
                QMessageBox.critical(self, "Decryption Error", f"An error occurred during decryption:\n{str(e)}")
        else:
            QMessageBox.warning(self, "Unsupported Method", "The selected encryption method is not supported yet.")

    def generate_encryption_key(self):
        key = get_random_bytes(16)
        return key.hex()

    def hex_key_to_bytes(self, key):
        return bytes.fromhex(key)

    def encrypt_data_aes(self, data, key):
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(pad(data.encode("utf-8"), AES.block_size))
        return cipher.nonce + ciphertext + tag

    def decrypt_data_aes(self, data, key):
        nonce = data[:16]
        ciphertext = data[16:-16]
        tag = data[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = unpad(cipher.decrypt_and_verify(ciphertext, tag), AES.block_size)
        return decrypted_data.decode("utf-8")

    def encrypt_data_rsa(self, data, public_key):
        cipher_rsa = PKCS1_OAEP.new(public_key)
        ciphertext = cipher_rsa.encrypt(data.encode("utf-8"))
        return ciphertext

    def decrypt_data_rsa(self, file_path, private_key):
        encrypted_data = lsb.reveal(file_path)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        plaintext = cipher_rsa.decrypt(bytes.fromhex(encrypted_data))
        return plaintext.decode("utf-8")

    def set_dark_mode(self):
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, Qt.black)

        self.setPalette(palette)
        self.dark_light_mode_button.setText("Light Mode")

    def set_light_mode(self):
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(240, 240, 240))
        palette.setColor(QPalette.WindowText, Qt.black)
        palette.setColor(QPalette.Base, QColor(255, 255, 255))
        palette.setColor(QPalette.AlternateBase, QColor(240, 240, 240))
        palette.setColor(QPalette.ToolTipBase, Qt.black)
        palette.setColor(QPalette.ToolTipText, Qt.black)
        palette.setColor(QPalette.Text, Qt.black)
        palette.setColor(QPalette.Button, QColor(240, 240, 240))
        palette.setColor(QPalette.ButtonText, Qt.black)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, Qt.white)

        self.setPalette(palette)
        self.dark_light_mode_button.setText("Dark Mode")

    def toggle_dark_light_mode(self):
        if self.dark_light_mode_button.text() == "Dark Mode":
            self.set_dark_mode()
        else:
            self.set_light_mode()

    def copy_encryption_key(self):
        encryption_key = self.encryption_key_input.text()
        clipboard = QApplication.clipboard()
        clipboard.setText(encryption_key)

    def clear_encryption_key(self):
        self.encryption_key_input.clear()

    def paste_decryption_key(self):
        clipboard = QApplication.clipboard()
        decryption_key = clipboard.text()
        self.decryption_key_input.setText(decryption_key)

    def clear_decryption_key(self):
        self.decryption_key_input.clear()

    def toggle_key_visibility(self, checked):
        if checked:
            # Introduce a small delay
            QApplication.processEvents()
            time.sleep(0.1)
            
            # Set echo mode
            QTimer.singleShot(0, lambda: self.encryption_key_input.setEchoMode(QLineEdit.PasswordEchoOnEdit))
            QTimer.singleShot(0, lambda: self.decryption_key_input.setEchoMode(QLineEdit.PasswordEchoOnEdit))
        else:
            self.encryption_key_input.setEchoMode(QLineEdit.Normal)
            self.decryption_key_input.setEchoMode(QLineEdit.Normal)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        file_path = event.mimeData().urls()[0].toLocalFile()
        self.file_path_label.setText(file_path)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.adjust_text_edit_sizes()

    def adjust_text_edit_sizes(self):
        width = self.decrypted_data_output.width()
        height = self.decrypted_data_output.height()
        self.data_to_embed_input.setMaximumHeight(height)
        self.decrypted_data_output.setMaximumHeight(height)


if __name__ == "__main__":
    app = QApplication([])
    window = PETGui()
    window.show()
    app.exec_()
