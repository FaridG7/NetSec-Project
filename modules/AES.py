import os
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import b64encode, b64decode

class AES:
    def derive_key_and_iv_from_a_text_and_salt(self, text: str, salt: bytes, iterations: int = 100_000):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=48,
            salt=salt,
            iterations=iterations,
        )
        key_iv = kdf.derive(text.encode())
        return key_iv[:32], key_iv[32:]
    @staticmethod
    def generate_random_key_and_iv():
        key = os.urandom(16)  
        iv = os.urandom(16)  
        return key, iv
    
    def encrypt(self, plaintext: str, key:bytes, iv:bytes) -> tuple[str, bytes, bytes]:
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return ciphertext

    def decrypt(self, ciphertext: str, key: bytes, iv: bytes) -> str:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()
