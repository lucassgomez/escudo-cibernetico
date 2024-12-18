from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
import os

def generate_key():
    """Gera uma chave aleatória de 256 bits para AES."""
    return os.urandom(32)

def encrypt_data(data, key):
    """Criptografa os dados utilizando AES (modo CBC)."""
    iv = os.urandom(16)  # Vetor de inicialização aleatório
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data  # Retorna IV + dados criptografados

def decrypt_data(encrypted_data, key):
    """Descriptografa os dados utilizando AES (modo CBC)."""
    iv = encrypted_data[:16]  # O IV está nos primeiros 16 bytes
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    return unpadded_data.decode()

def hash_data(data):
    """Gera o hash de dados usando SHA-256."""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data.encode())
    return digest.finalize().hex()
