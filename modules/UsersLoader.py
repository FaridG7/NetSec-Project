from pathlib import Path
import json

from modules.User import User

class UsersLoader:
    user: User | None
    users: list[User]

    def __init__(self):
        self.user = None
        self.users = self.load_users()
    
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