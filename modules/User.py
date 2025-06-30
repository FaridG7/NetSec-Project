import json
from pathlib import Path
from dataclasses import dataclass

from modules.HelperUtilities import HelperUtilities
from modules.RSA import RSA
from modules.Signature import Signature
from modules.exceptions import ConflictError,LoginFailed

@dataclass(frozen=True)
class User:
    username: str
    public_key_pem: bytes
    certificate: Signature

    @classmethod
    def from_dependencies(cls, username:str, public_key_pem: bytes, registrar_private_key_pem:bytes):
        return cls(
            username=username,
            public_key_pem=public_key_pem,
            certificate= RSA.sign_with_private_key(registrar_private_key_pem, str(f"username:{username},public_key:{public_key_pem}"))
        )

    def __str__(self):
        return f"username:{self.username},public_key:{self.public_key_pem},certificate:{str(self.certificate)},"

    @staticmethod
    def find_matched_user(username:str, users:list["User"])->"User" | None:
        return next((user for user in users if user["username"] == username), None)

    @staticmethod
    def login(users:list["User"], username: str)->"User":  
        matched_user = User.find_matched_user(username, users)
        if not matched_user:
            raise LoginFailed
        else:
            return matched_user
        
    @staticmethod
    def is_duplicate_user_name(users: list["User"], username: str) -> bool:
        return any(u['username'] == username for u in users)

    @staticmethod
    def dump_users_to_file(path: Path, users: list["User"]) -> None:
        with open(path, 'w') as f:
            json.dump(users, f, indent=2)

    @staticmethod
    def register_user(users:list["User"], username: str, registrar_private_key_pem:bytes):
        mutated_users = users.copy()
        if User.is_duplicate_user_name(users, username):
            raise ConflictError

        private_pem, public_pem = RSA.generate_pem_format_key_pair()

        HelperUtilities.generate_private_key_backup_file(username, private_pem)

        user = User.from_dependencies(username, public_pem, registrar_private_key_pem)
        mutated_users.append(user)

        path = Path('files') / 'users.json'
        User.dump_users_to_file(path, mutated_users)
        return private_pem