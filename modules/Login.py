import hashlib

from modules.User import User
from modules.exceptions import LoginFailed

class Login:
    def find_matched_user(self, username:str, users:list[User])->User | None:
        return next((user for user in users if user["username"] == username), None)

    def login(self, users:list[User], username: str)->User:  
        matched_user = self.find_matched_user(username, users)
        if not matched_user:
            raise LoginFailed
        else:
            return matched_user