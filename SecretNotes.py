from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from tkinter import messagebox
from tkinter import *
import base64
import sys
import os

# GUI
current_path = os.path.dirname(sys.argv[0])

Window = Tk()
Window.title('Secret Notes')
Window.config(padx=30, pady=30)

# Label
Label_1 = Label(text='Enter your title', font=('Arial', 15, 'normal'))
Label_2 = Label(text='Enter your secret', font=('Arial', 11, 'normal'))
Label_3 = Label(text='Enter master key', font=('Arial', 11, 'normal'))

# Entry
Entry_1 = Entry(width=30)
Entry_2 = Entry(width=30)

# Multiline
Multiline_1 = Text(width=30, height=10)

# Fernet
def encrypt():
    global fernet_cipher
    if not Entry_1.get() or not Multiline_1.get('1.0', END) or not Entry_2.get():
        messagebox.showwarning('Missing Fields', 'Please fill in all fields.')
        return

    password = Entry_2.get()

    salt = b'salt1234'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    fernet_cipher = Fernet(key)

    plaintext = Multiline_1.get('1.0', END)

    plaintext_bytes = plaintext.encode()

    ciphertext = fernet_cipher.encrypt(plaintext_bytes)

    file_path = os.path.join(current_path, Entry_1.get() + '.txt')
    with open(file_path, "wb") as file:
        file.write(ciphertext)

def decrypt():
    global fernet_cipher
    if not Entry_1.get() or not Entry_2.get():
        messagebox.showwarning('Missing Fields', 'Please fill in all fields.')
        return

    password = Entry_2.get()

    salt = b'salt1234'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    fernet_cipher = Fernet(key)

    try:
        file_path = os.path.join(current_path, Entry_1.get() + '.txt')
        with open(file_path, "rb") as file:
            ciphertext = file.read()

        plaintext_bytes = fernet_cipher.decrypt(ciphertext)
        plaintext = plaintext_bytes.decode()

        Multiline_1.delete('1.0', END)
        Multiline_1.insert('1.0', plaintext)
    except FileNotFoundError:
        messagebox.showwarning('File Not Found', 'The specified file was not found.')
    except base64.binascii.Error:
        messagebox.showwarning('Incorrect Key', 'The master key entered is incorrect.')
    except InvalidToken:
        messagebox.showwarning('Invalid Token', 'The master key entered is incorrect.')

# Button
Button_1 = Button(text='Save & Encrypt', command=encrypt)
Button_2 = Button(text='Decrypt', command=decrypt)

# Packing
Label_1.pack(pady=5)
Entry_1.pack(pady=5)
Entry_1.focus()
Label_2.pack(pady=5)
Multiline_1.pack(pady=5)
Label_3.pack(pady=5)
Entry_2.pack(pady=5)
Button_1.pack(pady=15)
Button_2.pack(pady=5)

Window.mainloop()