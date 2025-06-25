from pathlib import Path
import json

from modules.User import User

class LoadUsers:
    def laod_users(self)->list[User]:
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
