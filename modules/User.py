import json
from pathlib import Path

from modules.RSA import RSA
from modules.Signature import Signature
from modules.exceptions import ConflictError,LoginFailed


class User:
    username: str
    public_key: str
    certificate: Signature

    def __init__(self, username:str, public_key:str, registrar_username:str|None = None, registrar_private_key_pem: bytes|None = None, signature: Signature|None = None):
        self.username = username
        self.public_key = public_key
        if not signature and registrar_username and registrar_private_key_pem:
            self.certificate = self.sign_with_private_key(registrar_private_key_pem, str(f"username: {self.username},password: {self.password},salt: {self.salt},public_key: {self.public_key},registrar username: {registrar_username}"))
        elif signature and not(registrar_username or registrar_private_key_pem):
            self.certificate = signature
        else:
            raise Exception('bad usage of the User class init method.')

    def __str__(self):
        return f"username: {self.username},password: {self.password},salt: {self.salt},public_key: {self.public_key},signature: {str(self.certificate['signature'])},"

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
    def register_user(users:list["User"], username: str, registrar_username:str, registrar_private_key_pem:bytes) -> tuple[list["User"], dict[str, "User"|bytes]]:
        mutated_users = users.copy()
        if User.is_duplicate_user_name(users, username):
            raise ConflictError

        private_pem, public_pem = RSA.generate_pem_format_key_pair()

        user = User(username, public_pem, registrar_username,registrar_private_key_pem)
        mutated_users.append(user)

        path = Path('files') / 'users.json'
        User.dump_users_to_file(path, mutated_users)

        return mutated_users, {
            "user": user,
            "private_key": private_pem
        }