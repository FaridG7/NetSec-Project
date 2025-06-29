from pathlib import Path
import json

from modules.User import User

class Loader:
    root_certificate_public_pem:bytes
    user: User | None
    users: list[User]
    cached_messages: dict[User,str]

    def __init__(self):
        self.root_certificate_public_pem = self.load_root_certificate()
        self.user = None
        self.users = self.load_users()
        self.cached_messages = {}
        
    def load_users(self)->list[User]:
        path = Path('files') / 'users.json'
        path.parent.mkdir(parents=True, exist_ok=True)

        if path.exists():
            try:
                with open(path) as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return []
        else:
            return []
        
    def load_root_certificate(self)->bytes:
        path = Path('files') / 'root_certificate.pem'
        if path.exists():
            with open(path, 'rb') as f:
                return f.read()