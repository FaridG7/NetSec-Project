from modules.RSA import RSA
from modules.Signature import Signature


class User(RSA):
    username: str
    public_key: str
    signature: Signature

    def __init__(self, username:str, public_key:str, registrar_username:str|None = None, registrar_private_key_pem: bytes|None = None, signature: Signature|None = None):
        self.username = username
        self.public_key = public_key
        if not signature and registrar_username and registrar_private_key_pem:
            self.signature = self.sign_with_private_key(registrar_private_key_pem, str(f"username: {self.username},password: {self.password},salt: {self.salt},public_key: {self.public_key},registrar username: {registrar_username}"))
        elif signature and not(registrar_username or registrar_private_key_pem):
            self.signature = signature
        else:
            raise Exception('bad usage of the User class init method.')

    def __str__(self):
        return f"username: {self.username},password: {self.password},salt: {self.salt},public_key: {self.public_key},signature: {str(self.signature['signature'])},"
