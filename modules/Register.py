import re
import os
import json
import hashlib
from pathlib import Path

from modules.RSA import RSA
from modules.types import User
from modules.exceptions import BadInput, ConflictError

class Register(RSA):
    def is_duplicate_user_name(self, users: list[User], username: str) -> bool:
        return any(u['username'] == username for u in users)

    def is_valid_password(self, password: str) -> bool:
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

    def hash_password(self, password:str)->tuple[str, bytes]:
        salt = os.urandom(16)
        salted_password = salt + password.encode()
        hash_digest = hashlib.sha256(salted_password).hexdigest()
        return hash_digest, salt.hex()

    def dump_users_to_file(self, path: Path, users: list[User]) -> None:
        with open(path, 'w') as f:
            json.dump(users, f, indent=2)

    def register_user(self, users:list[User], username: str, password: str) -> dict[str, str]:
        if self.is_duplicate_user_name(users, username):
            raise ConflictError

        if not self.is_valid_password(password):
            raise BadInput

        private_pem, public_pem = self.generate_pem_format_key_pair()

        hashed_password, salt_string = self.hash_password(password)
        user = {"username": username, "password": hashed_password, "salt":salt_string, "public_key": public_pem.decode()}
        users.append(user)

        path = Path('files') / 'users.json'
        self.dump_users_to_file(path, users)

        return {
            "user": user,
            "private_key": private_pem.decode()
        }
