import hashlib
import os
from pathlib import Path
import re

from modules.AES import AES
from modules.exceptions import BadInput, PasswordHashFileNotFound, PrivateKeyFileNotFound


class SafeHandler(AES):
    def forge_file_name(self, username:str, password:str, salt:bytes):
        return hashlib.sha256(username.encode() + password.encode() + salt).hexdigest()

    def store_private_key(self, username:str, password:str, salt:bytes, private_key:str)->None:
        file_name = self.forge_file_name(username, password, salt)
        path = Path('files/safe') / username / f"{file_name}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            key, iv = self.derive_key_and_iv_from_a_text_and_salt(password, salt)
            cipher_text = self.encrypt(private_key, key, iv)
            f.write(cipher_text)


    def is_valid_password_format(self, password: str) -> bool:
        if not 8 <= len(password) <= 16:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'\d', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True
    
    def hash_password(self, password:str)->tuple[str, str]:
        salt = os.urandom(16)
        salted_password = salt + password.encode()
        hash_digest = hashlib.sha256(salted_password).hexdigest()
        return hash_digest, salt.hex()

    def store_password(self, username:str, password:str):
        if not self.is_valid_password_format(password):
            raise BadInput

        hash_digest, salt_str = self.hash_password(password)

        path = Path('files/safe') / username / "password.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            f.write(f"{hash_digest}\n{salt_str}")

    def restore_password_hash_from_file(username:str):
        path = Path('files/safe') / username / "password.txt"
        try:
            with open(path) as f:
                s = f.read()
                hash_digest, salt_str = s.split("\n")
                return hash_digest, salt_str
        except FileNotFoundError:
            raise PasswordHashFileNotFound()

    def is_password_verified(self, password:str)->bool:
        hash_digest, salt_hex = self.restore_password_hash_from_file()

        salt = bytes.fromhex(salt_hex)

        salted_input = salt + password.encode()
        new_hash = hashlib.sha256(salted_input).hexdigest()
        
        return new_hash == hash_digest
    
    def load_private_key(self, username:str, password:str, salt:bytes)->str | None:
        file_name = self.forge_file_name(username, password, salt)
        path = Path('files/safe') / username / f"{file_name}.txt"
        try:
            with open(path) as f:
                cipher_text = f.read()
                key, iv = self.derive_key_and_iv_from_a_text_and_salt(password, salt)
                return self.decrypt(cipher_text, key, iv)
        except FileNotFoundError:
            raise PrivateKeyFileNotFound()