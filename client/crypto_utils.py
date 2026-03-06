from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import json

class CryptoManager:
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.backend = default_backend()
    
    def generate_rsa_keys(self):
        """Генерирует пару RSA ключей (2048 бит)"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        self.public_key = self.private_key.public_key()
        return self.get_public_key_pem()
    
    def get_public_key_pem(self):
        """Возвращает публичный ключ в формате PEM строки"""
        if not self.public_key:
            return None
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def get_private_key_pem(self):
        """Возвращает приватный ключ в формате PEM строки"""
        if not self.private_key:
            return None
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    
    def load_private_key(self, pem_data):
        """Загружает приватный ключ из PEM строки"""
        self.private_key = serialization.load_pem_private_key(
            pem_data.encode('utf-8'),
            password=None,
            backend=self.backend
        )
        self.public_key = self.private_key.public_key()
    
    def encrypt_aes(self, message: str, key: bytes) -> tuple:
        """
        Шифрует сообщение AES-256 в режиме GCM
        Возвращает (ciphertext, nonce, tag) в base64
        """
        # Генерируем случайный nonce (12 байт для GCM)
        nonce = os.urandom(12)
        
        # Создаем шифр
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Шифруем
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        
        # Получаем тег аутентификации
        tag = encryptor.tag
        
        # Кодируем в base64 для передачи
        return (
            base64.b64encode(ciphertext).decode('utf-8'),
            base64.b64encode(nonce).decode('utf-8'),
            base64.b64encode(tag).decode('utf-8')
        )
    
    def decrypt_aes(self, ciphertext_b64: str, nonce_b64: str, tag_b64: str, key: bytes) -> str:
        """Дешифрует сообщение AES-256 GCM"""
        # Декодируем из base64
        ciphertext = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        
        # Создаем дешифратор
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # Дешифруем
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode('utf-8')
    
    def encrypt_for_recipient(self, message: str, recipient_public_key_pem: str) -> dict:
        """
        Полный цикл шифрования сообщения для получателя:
        1. Генерируем случайный AES ключ
        2. Шифруем сообщение AES-256
        3. Шифруем AES ключ публичным ключом получателя (RSA)
        """
        # Генерируем случайный AES ключ (32 байта для AES-256)
        aes_key = os.urandom(32)
        
        # Шифруем сообщение AES-256
        ciphertext, nonce, tag = self.encrypt_aes(message, aes_key)
        
        # Загружаем публичный ключ получателя
        recipient_key = serialization.load_pem_public_key(
            recipient_public_key_pem.encode('utf-8'),
            backend=self.backend
        )
        
        # Шифруем AES ключ RSA
        encrypted_aes_key = recipient_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return {
            "ciphertext": ciphertext,
            "nonce": nonce,
            "tag": tag,
            "encrypted_key": base64.b64encode(encrypted_aes_key).decode('utf-8')
        }
    
    def decrypt_from_sender(self, encrypted_data: dict, sender_public_key_pem: str = None) -> str:
        """
        Полный цикл дешифровки сообщения от отправителя:
        1. Расшифровываем AES ключ своим приватным ключом RSA
        2. Расшифровываем сообщение AES-256
        """
        # Декодируем зашифрованный AES ключ
        encrypted_aes_key = base64.b64decode(encrypted_data["encrypted_key"])
        
        # Расшифровываем AES ключ своим приватным ключом
        aes_key = self.private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Дешифруем сообщение
        plaintext = self.decrypt_aes(
            encrypted_data["ciphertext"],
            encrypted_data["nonce"],
            encrypted_data["tag"],
            aes_key
        )
        
        return plaintext
    
    @staticmethod
    def generate_salt() -> str:
        """Генерирует соль для хранения ключей"""
        return base64.b64encode(os.urandom(16)).decode('utf-8')