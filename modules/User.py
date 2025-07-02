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
            certificate= Signature.from_dependencies(f"username:{username},public_key:{public_key_pem}", registrar_private_key_pem) 
        )
    
    def to_dict(self)->dict[str, str | bytes | dict[str, str]]:
         return {
        "username": self.username,
        "public_key_pem": self.public_key_pem.hex(),
        "certificate": self.certificate.to_dict()
    }

    @staticmethod
    def from_dict(data):
        return User(
        username=data["username"],
        public_key_pem=bytes.fromhex(data["public_key_pem"]),
        certificate=Signature.from_dict(data["certificate"])
    )

    def __str__(self):
        return f"username:{self.username},public_key:{self.public_key_pem},certificate:{str(self.certificate)},"

    @staticmethod
    def find_matched_user(username: str, users: list["User"]) -> "User | None":
        return next((user for user in users if user.username == username), None)

    @staticmethod
    def login(users:list["User"], username: str)->"User":  
        matched_user = User.find_matched_user(username, users)
        if not matched_user:
            raise LoginFailed
        else:
            return matched_user
        
    @staticmethod
    def is_duplicate_user_name(users: list["User"], username: str) -> bool:
        return any(u.username == username for u in users)

    @staticmethod
    def dump_users_to_file(users: list["User"]) -> None:
        path = Path('files') / 'users.json'
        with open(path, 'w') as f:
            json.dump([u.to_dict() for u in users], f, indent=2)

    @staticmethod
    def load_users()->list["User"]:
        path = Path('files') / 'users.json'
        path.parent.mkdir(parents=True, exist_ok=True)

        if path.exists():
            try:
                with open(path) as f:
                    data =  json.load(f)
                    return [User.from_dict(u) for u in data]
            except json.JSONDecodeError:
                return []
        else:
            return []
      
    @staticmethod
    def register_user(users:list["User"], username: str, registrar_private_key_pem:bytes):
        mutated_users = users.copy()
        if User.is_duplicate_user_name(users, username):
            raise ConflictError

        private_pem, public_pem = RSA.generate_pem_format_key_pair()

        user = User.from_dependencies(username, public_pem, registrar_private_key_pem)
        mutated_users.append(user)


        HelperUtilities.generate_private_key_backup_file(username, private_pem)
        User.dump_users_to_file(mutated_users)

        return mutated_users, private_pem