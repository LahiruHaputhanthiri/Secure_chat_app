import tkinter as tk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat App")
        self.root.configure(bg='light blue')

        # Generate symmetric keys
        self.symmetric_key_user_one = self.generate_key()
        self.symmetric_key_user_two = self.generate_key()

        # Create User One frame
        self.user_one_frame = tk.Frame(root, bg='light blue')
        self.user_one_frame.grid(row=0, column=0, padx=10, pady=10)

        self.label_user_one = tk.Label(self.user_one_frame, text="User One", bg='light blue')
        self.label_user_one.grid(row=0, column=0, columnspan=2)

        self.entry_user_one = tk.Entry(self.user_one_frame)
        self.entry_user_one.grid(row=1, column=0)

        self.button_encrypt_user_one = tk.Button(self.user_one_frame, text="Encrypt & Send", bg="#ed3833", fg="white", command=lambda: self.encrypt('User One'))
        self.button_encrypt_user_one.grid(row=1, column=1)

        self.conversation_user_one = tk.Text(self.user_one_frame, height=10, width=50)
        self.conversation_user_one.grid(row=2, column=0, columnspan=2)

        self.label_secret_user_one = tk.Label(self.user_one_frame, text="Secret Key:", bg='light blue')
        self.label_secret_user_one.grid(row=3, column=0)

        self.entry_secret_user_one = tk.Entry(self.user_one_frame)
        self.entry_secret_user_one.grid(row=3, column=1)

        self.button_secret_user_one = tk.Button(self.user_one_frame, text="Set Secret Key", bg="#1089ff", fg="white", command=lambda: self.set_secret_key('User One'))
        self.button_secret_user_one.grid(row=4, column=0, columnspan=2)

        # Create User Two frame
        self.user_two_frame = tk.Frame(root, bg='light blue')
        self.user_two_frame.grid(row=1, column=0, padx=10, pady=10)

        self.label_user_two = tk.Label(self.user_two_frame, text="User Two", bg='light blue')
        self.label_user_two.grid(row=0, column=0, columnspan=2)

        self.entry_user_two = tk.Entry(self.user_two_frame)
        self.entry_user_two.grid(row=1, column=0)

        self.button_encrypt_user_two = tk.Button(self.user_two_frame, text="Encrypt & Send", bg="#ed3833", fg="white", command=lambda: self.encrypt('User Two'))
        self.button_encrypt_user_two.grid(row=1, column=1)

        self.conversation_user_two = tk.Text(self.user_two_frame, height=10, width=50)
        self.conversation_user_two.grid(row=2, column=0, columnspan=2)

        self.label_secret_user_two = tk.Label(self.user_two_frame, text="Secret Key:", bg='light blue')
        self.label_secret_user_two.grid(row=3, column=0)

        self.entry_secret_user_two = tk.Entry(self.user_two_frame)
        self.entry_secret_user_two.grid(row=3, column=1)

        self.button_secret_user_two = tk.Button(self.user_two_frame, text="Set Secret Key", bg="#1089ff", fg="white", command=lambda: self.set_secret_key('User Two'))
        self.button_secret_user_two.grid(row=4, column=0, columnspan=2)

    def generate_key(self):
        return os.urandom(32)

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

    def encrypt_message(self, message, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(message.encode()) + encryptor.finalize()
        return iv + ct

    def decrypt_message(self, ciphertext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def set_secret_key(self, sender):
        if sender == 'User One':
            secret_key = self.entry_secret_user_one.get()
            self.secret_key_user_one = secret_key.encode()
        else:
            secret_key = self.entry_secret_user_two.get()
            self.secret_key_user_two = secret_key.encode()

    def encrypt(self, sender):
        if sender == 'User One':
            plain_text = self.entry_user_one.get()
            encrypted_message = self.encrypt_message(plain_text, self.symmetric_key_user_one)
            encrypted_message = base64.b64encode(encrypted_message).decode()

            self.conversation_user_two.insert(tk.END, "User One: " + encrypted_message + "\n")
            self.conversation_user_two.insert(tk.END, "\n")
        else:
            plain_text = self.entry_user_two.get()
            encrypted_message = self.encrypt_message(plain_text, self.symmetric_key_user_two)
            encrypted_message = base64.b64encode(encrypted_message).decode()

            self.conversation_user_one.insert(tk.END, "User Two: " + encrypted_message + "\n")
            self.conversation_user_one.insert(tk.END, "\n")

    def decrypt(self, sender):
        if sender == 'User One':
            encrypted_message = base64.b64decode(self.entry_user_one.get().split("Encrypted message: ")[-1].strip())
            iv = encrypted_message[:16]
            ciphertext = encrypted_message[16:]
            plain_text = self.decrypt_message(ciphertext, self.symmetric_key_user_two, iv).decode()
            self.conversation_user_one.insert(tk.END, "User Two: " + plain_text + "\n")
            self.conversation_user_one.insert(tk.END, "Decrypted message: " + plain_text + "\n")
            self.conversation_user_one.insert(tk.END, "\n")
        else:
            encrypted_message = base64.b64decode(self.entry_user_two.get().split("Encrypted message: ")[-1].strip())
            iv = encrypted_message[:16]
            ciphertext = encrypted_message[16:]
            plain_text = self.decrypt_message(ciphertext, self.symmetric_key_user_one, iv).decode()
            self.conversation_user_two.insert(tk.END, "User One: " + plain_text + "\n")
            self.conversation_user_two.insert(tk.END, "Decrypted message: " + plain_text + "\n")
            self.conversation_user_two.insert(tk.END, "\n")

# Initialize Tkinter
root = tk.Tk()
app = ChatApp(root)
root.mainloop()
