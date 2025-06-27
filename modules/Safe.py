from pathlib import Path

from modules.AES import AES
from modules.HelperUtilities import HelperUtilities
from modules.exceptions import BadInput, PasswordHashFileNotFound, PrivateKeyFileNotFound


class Safe:
    @staticmethod
    def store_password_hash_in_file(username:str, password:str):
        if not HelperUtilities.is_valid_password_format(password):
            raise BadInput

        hash_digest, salt_str = HelperUtilities.hash_password(password)

        path = Path('files/safe') / username / "password.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            f.write(f"{hash_digest}\n{salt_str}")

    @staticmethod
    def restore_password_hash_from_file(username:str):
        path = Path('files/safe') / username / "password_hash.txt"
        try:
            with open(path) as f:
                s = f.read()
                hash_digest, salt_str = s.split("\n")
                return hash_digest, salt_str
        except FileNotFoundError:
            raise PasswordHashFileNotFound()

    @staticmethod
    def store_private_key_locally(username:str, password:str, salt_str:str, private_key_pem:bytes)->None:
        path = Path('files/safe') / username / "safe.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            key, iv = AES.derive_key_and_iv_from_two_texts(password, salt_str)
            cipher_text = AES.encrypt(private_key_pem.decode(), key, iv)
            f.write(cipher_text)

    @staticmethod
    def load_locally_private_key(username:str, password:str, salt_str:str)->bytes:
        path = Path('files/safe') / username / "safe.txt"
        try:
            with open(path) as f:
                cipher_text = f.read()
                key, iv = AES.derive_key_and_iv_from_two_texts(password, salt_str)
                private_key =  AES.decrypt(cipher_text, key, iv)
                return private_key.encode()

        except FileNotFoundError:
            raise PrivateKeyFileNotFound()