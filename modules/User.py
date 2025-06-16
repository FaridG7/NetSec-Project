from typing import TypedDict

class User(TypedDict):
    username: str
    password: str
    salt: str
    public_key: str
