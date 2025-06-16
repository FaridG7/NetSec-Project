import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode


class SafeUtils:
    def __init__(self):
        self.backend = default_backend()
        
    def derive_key_and_iv(self, password: str, salt: bytes, iterations: int = 100_000):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=48,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        key_iv = kdf.derive(password.encode())
        return key_iv[:32], key_iv[32:]


    def encrypt(self, plaintext: str, password: str, salt: bytes) -> str:
        key, iv = self.derive_key_and_iv(password, salt)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return b64encode(salt + ciphertext).decode()

    def decrypt(self, encrypted: str, password: str) -> str:
        data = b64decode(encrypted)
        salt, ciphertext = data[:16], data[16:]
        key, iv = self.derive_key_and_iv(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()

    def forge_file_name(self, username:str, password:str, salt:bytes):
        return hashlib.sha256(salt + username.encode() + password.encode()).hexdigest()

    def store_private_key(self, username:str, password:str, salt:bytes, private_key:str)->None:
        file_name = self.forge_file_name(username, password, salt)
        path = Path('files/safe') / f"{file_name}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            cipher_text = self.encrypt(private_key, password, salt)
            f.write(cipher_text)

    def read_private_key(self, username:str, password:str, salt:bytes)->str | None:
        file_name = self.forge_file_name(username, password, salt)
        path = Path('files/safe') / f"{file_name}.txt"
        try:
            with open(path) as f:
                cipher_text = f.read()
                return self.decrypt(cipher_text, password)
        except FileNotFoundError:
            return None
