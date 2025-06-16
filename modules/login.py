from load_users import load_users
from exceptions import LoginFailed
from typing import Dict
import hashlib

def find_matched_user(username, users)->Dict[str, str, str, str]:
    return next((user for user in users if user["username"] == username), None)

def verify_password(entered_password: str, stored_hash: str, stored_salt_hex: str) -> bool:
    salt = bytes.fromhex(stored_salt_hex)
    salted_input = salt + entered_password.encode()
    new_hash = hashlib.sha256(salted_input).hexdigest()
    return new_hash == stored_hash

def login(username, password)->Dict[str, str, str, str]:  
    users = load_users()
    matched_user = find_matched_user(username,users)
    if not matched_user:
        raise LoginFailed
    if verify_password(password, matched_user['password'], matched_user['salt']):
        return matched_user
    else:
        raise LoginFailed