from pathlib import Path
import json
from MailBox import User

def load_users()->list[User]:
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
