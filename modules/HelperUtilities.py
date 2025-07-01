import os
from pathlib import Path
import re
import string
import hashlib
import secrets


class HelperUtilities:
    @staticmethod
    def is_certificate_valid(public_pem:bytes):
        return  hashlib.sha256(public_pem).digest() == b'\xb4n\xa4\xf7\xa3O\xaf\xfc\xb0\x11\xc0NS\xd3\x90l\x82~_.\x11\x95"[\xd71U\x04\rD\xb6\xab'

    @staticmethod
    def generate_random_text(length:int):
        chars = string.ascii_letters + string.digits
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    @staticmethod
    def is_valid_password_format(password: str) -> bool:
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
    def hash_password(password:str)->tuple[bytes, bytes]:
        salt = os.urandom(16)
        salted_password = salt + password.encode()
        hash_digest = hashlib.sha256(salted_password).digest()
        return hash_digest, salt

    @staticmethod
    def is_password_verified(password:str, hash_digest:bytes, salt:bytes)->bool:
        salted_input = salt + password.encode()
        new_hash = hashlib.sha256(salted_input).digest()
        
        return new_hash == hash_digest

    @staticmethod
    def generate_private_key_backup_file(username:str, private_key_pem:bytes)->None:
        path = Path('.') / f"{username}_private_key.pem"
        with open(path, 'wb') as f:
            f.write(private_key_pem)
    
    @staticmethod
    def restore_private_key_from_backup_file(path:str)->bytes:
        with open(path, 'rb') as f:
            private_key_pem = f.read()
            return private_key_pem
    
    @staticmethod
    def find_messages_count()-> int:
        directory_path = Path('files/messages')
        message_files = os.listdir(directory_path)
        return len(message_files)