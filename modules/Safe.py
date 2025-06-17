import hashlib
from pathlib import Path

from modules.AES import AES


class SafeHandler(AES):
    def forge_file_name(self, username:str, password:str, salt:bytes):
        return hashlib.sha256(salt + username.encode() + password.encode()).hexdigest()

    def store_private_key(self, username:str, password:str, salt:bytes, private_key:str)->None:
        file_name = self.forge_file_name(username, password, salt)
        path = Path('files/safe') / f"{file_name}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            key, iv = self.derive_key_and_iv_from_a_text_and_salt(password, salt)
            cipher_text = self.encrypt(private_key, key, iv)
            f.write(cipher_text)

    def load_private_key(self, username:str, password:str, salt:bytes)->str | None:
        file_name = self.forge_file_name(username, password, salt)
        path = Path('files/safe') / f"{file_name}.txt"
        try:
            with open(path) as f:
                cipher_text = f.read()
                key, iv = self.derive_key_and_iv_from_a_text_and_salt(password, salt)
                return self.decrypt(cipher_text, key, iv)
        except FileNotFoundError:
            return None