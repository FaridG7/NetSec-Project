from pathlib import Path

from modules.User import User

class Loader:
    root_certificate_public_pem:bytes
    user: User | None
    users: list[User]
    cached_messages: dict[User,str]

    def __init__(self):
        self.root_certificate_public_pem = Loader.load_root_certificate()
        self.user = None
        self.users = User.load_users()
        self.cached_messages = {}
    @staticmethod
    def load_root_certificate()->bytes:
        path = Path('files') / 'root_certificate.pem'
        if path.exists():
            with open(path, 'rb') as f:
                return f.read()
        else:
            raise