import os
import json
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from MailBox import User
from exceptions import ConflictError

class Register:
    def check_for_duplicate_user_names(self, users: list[User], username: str) -> bool:
        return any(u['username'] == username for u in users)
            
    def generate_pem_format_key_pair(self) -> tuple[bytes, bytes]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem

    def hash_password(self, password:str)->tuple[str, bytes]:
        salt = os.urandom(16)
        salted_password = salt + password.encode()
        hash_digest = hashlib.sha256(salted_password).hexdigest()
        return hash_digest, salt.hex()

    def dump_username_to_file(self, path: Path, users: list[User]) -> None:
        with open(path, 'w') as f:
            json.dump(users, f, indent=2)

    def register_user(self, users:list[User], username: str, password: str) -> dict[str, str]:
        if self.check_for_duplicate_user_names(users, username):
            raise ConflictError

        private_pem, public_pem = self.generate_pem_format_key_pair()

        hashed_password, salt = self.hash_password(password)

        users.append({"username": username, "password": hashed_password, "salt":salt, "public_key": public_pem.decode()})

        path = Path('files') / 'users.json'
        self.dump_username_to_file(path, users)

        return {
            "username": username,
            "public_key": public_pem.decode(),
            "private_key": private_pem.decode()
        }
