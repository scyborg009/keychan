from cryptography.fernet import Fernet
import os

def get_encryption_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as f:
            f.write(key)
    else:
        with open("secret.key", "rb") as f:
            key = f.read()
    return key

def encrypt_data(data: str, key: bytes) -> bytes:
    return Fernet(key).encrypt(data.encode())

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    return Fernet(key).decrypt(encrypted_data).decode()