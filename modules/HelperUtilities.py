import os
from pathlib import Path
import re
import string
import hashlib
import secrets

from modules.Safe import Safe


class HelperUtilities:
    @staticmethod
    def generate_random_text(length:int):
        chars = string.ascii_letters + string.digits
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    @staticmethod
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
    
    @staticmethod
    def hash_password(password:str)->tuple[str, str]:
        salt = os.urandom(16)
        salted_password = salt + password.encode()
        hash_digest = hashlib.sha256(salted_password).hexdigest()
        return hash_digest, salt.hex()

    @staticmethod
    def is_password_verified(password:str, hash_digest:str, salt_hex:str)->bool:
        salt = bytes.fromhex(salt_hex)

        salted_input = salt + password.encode()
        new_hash = hashlib.sha256(salted_input).hexdigest()
        
        return new_hash == hash_digest

    @staticmethod
    def generate_private_key_backup_file(private_pem:bytes)->None:
        path = Path('.') / "private_key.txt"
        with open(path), 'w' as f:
            f.write(private_pem)
    
    @staticmethod
    def restore_private_key_backup(username:str, password:str, salt_str:str, path:str)->str:
        with open(path, 'r') as f:
            private_pem = f.read()
            Safe.store_private_key_locally(username, password, salt_str, private_pem)
            return private_pem