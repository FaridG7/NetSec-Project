from pathlib import Path
import json
from typing import List, Dict

def load_users()->List[Dict[str, str, str, str]]:
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
