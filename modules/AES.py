import os
import base64
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class AES:
    @staticmethod
    def derive_key_and_iv_from_two_texts(text: str, salt_hex: str, iterations: int = 100_000):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=48,
            salt=bytes.fromhex(salt_hex),
            iterations=iterations,
        )
        key_iv = kdf.derive(text.encode())
        return key_iv[:32], key_iv[32:]
    
    @staticmethod
    def generate_random_key_and_iv():
        key = os.urandom(16)  
        iv = os.urandom(16)  
        return key, iv
    
    @staticmethod
    def encrypt(plaintext: str, key:bytes, iv:bytes)->bytes:
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(cipher_text).decode()

    @staticmethod
    def decrypt(cipher_text_b64: str, key: bytes, iv: bytes) -> str:
        cipher_text = base64.b64decode(cipher_text_b64)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(cipher_text) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()
