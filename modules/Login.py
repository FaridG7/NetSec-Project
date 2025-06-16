import hashlib

from modules.User import User
from modules.exceptions import LoginFailed

class Login:
    def find_matched_user(self, username:str, users:list[User])->User | None:
        return next((user for user in users if user["username"] == username), None)

    def verify_password(self, entered_password: str, stored_hash: str, stored_salt_hex: str) -> bool:
        salt = bytes.fromhex(stored_salt_hex)
        salted_input = salt + entered_password.encode()
        new_hash = hashlib.sha256(salted_input).hexdigest()
        return new_hash == stored_hash

    def login(self, users:list[User], username: str, password:str)->User:  
        matched_user = self.find_matched_user(username, users)
        if not matched_user:
            raise LoginFailed
        if self.verify_password(password, matched_user['password'], matched_user['salt']):
            return matched_user
        else:
            raise LoginFailed