import json
from pathlib import Path

from modules.RSA import RSA
from modules.User import User
from modules.exceptions import ConflictError

class Register(RSA):
    def is_duplicate_user_name(self, users: list[User], username: str) -> bool:
        return any(u['username'] == username for u in users)

    def dump_users_to_file(self, path: Path, users: list[User]) -> None:
        with open(path, 'w') as f:
            json.dump(users, f, indent=2)

    def register_user_in_broadcast_file(self, users:list[User], username: str, registrar_username:str, registrar_private_key_pem:bytes) -> tuple[list[User], dict[str, User|str]]:
        mutated_users = users.copy()
        if self.is_duplicate_user_name(users, username):
            raise ConflictError

        private_pem, public_pem = self.generate_pem_format_key_pair()

        user = User(username, public_pem, registrar_username,registrar_private_key_pem)
        mutated_users.append(user)

        path = Path('files') / 'users.json'
        self.dump_users_to_file(path, mutated_users)

        return mutated_users, {
            "user": user,
            "private_key": private_pem.decode()
        }

    def register_user(self, users:list[User], username: str, password: str) -> dict[str, str]:
        mutated_users, registered_user = self.register_user_in_broadcast_file(users, username, password)