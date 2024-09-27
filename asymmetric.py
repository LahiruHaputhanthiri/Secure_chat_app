import tkinter as tk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

class ChatWindow:
    def __init__(self, name):
        self.name = name
        self.messages = []

        # Initialize Tkinter window
        self.root = tk.Tk()
        self.root.title(name)

        # Set background color
        self.root.configure(bg='light blue')

        # Initialize variables for symmetric key and salt
        self.symmetric_key = None
        self.salt = None

        # Create secret key entry field
        self.secret_key_frame = tk.Frame(self.root, bg='light blue')
        self.secret_key_frame.pack(pady=5)

        self.secret_key_label = tk.Label(self.secret_key_frame, text="Secret Key:", bg='light blue')
        self.secret_key_label.pack(side='left')

        self.secret_key_entry = tk.Entry(self.secret_key_frame, show="*")
        self.secret_key_entry.pack(side='left')

        self.secret_key_button = tk.Button(self.secret_key_frame, text="Set Secret Key", bg="#1089ff", fg="white", command=self.set_secret_key)
        self.secret_key_button.pack(side='left')

        # Create password entry field
        self.password_frame = tk.Frame(self.root, bg='light blue')
        self.password_frame.pack(pady=5)

        self.password_label = tk.Label(self.password_frame, text="Password:", bg='light blue')
        self.password_label.pack(side='left')

        self.password_entry = tk.Entry(self.password_frame, show="*")
        self.password_entry.pack(side='left')

        self.password_button = tk.Button(self.password_frame, text="Set Password", bg="#1089ff", fg="white", command=self.set_password)
        self.password_button.pack(side='left')

        # Create message entry field
        self.entry_frame = tk.Frame(self.root, bg='light blue')
        self.entry_frame.pack(pady=10)

        self.entry = tk.Entry(self.entry_frame)
        self.entry.pack(side='left', padx=5)

        self.entry_button = tk.Button(self.entry_frame, text="Send Message", bg="#ed3833", fg="white", command=self.send_message)
        self.entry_button.pack(side='left')

        # Create message display area
        self.message_display = tk.Text(self.root, height=10, width=50)
        self.message_display.pack(pady=10)

    def derive_key(self, password):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key, salt

    def encrypt_message(self, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.symmetric_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(message) + encryptor.finalize()
        return iv + ct

    def set_secret_key(self):
        secret_key = self.secret_key_entry.get()
        if secret_key:
            self.symmetric_key, self.salt = self.derive_key(secret_key)
            self.secret_key_entry.config(state='readonly')  # Set the entry to read-only
        else:
            print("Please enter a secret key!")

    def set_password(self):
        password = self.password_entry.get()
        if password:
            print("Password set successfully.")
            self.password_entry.config(state='readonly')  # Set the entry to read-only
        else:
            print("Please enter a password!")

    def send_message(self):
        secret_key = self.secret_key_entry.get()
        password = self.password_entry.get()
        message = self.entry.get().encode()
        
        if not secret_key or not password:
            print("Please set both secret key and password.")
            return
        
        if self.symmetric_key is None:
            self.symmetric_key, self.salt = self.derive_key(secret_key)
        
        encrypted_message = self.encrypt_message(message)
        self.messages.append((self.name, base64.b64encode(encrypted_message).decode()))
        self.display_message((self.name, message.decode()))

    def display_message(self, message):
        user, text = message
        self.message_display.insert(tk.END, f"{user}: {text}\n")

def main():
    # Create Alice window
    alice_window = ChatWindow("User One")

    # Create Bob window
    bob_window = ChatWindow("User Two")

    # Run the Tkinter event loop
    alice_window.root.mainloop()
    bob_window.root.mainloop()

if __name__ == "__main__":
    main()
