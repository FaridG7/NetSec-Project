from pathlib import Path

from modules.AES import AES
from modules.HelperUtilities import HelperUtilities
from modules.Message import MessageBody
from modules.exceptions import BadInput, PasswordHashFileNotFound, PrivateKeyFileNotFound


seperator1 = "-------------------------------------------------------------------------------------------------------\n"
seperator2 = ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n"

class Safe:
    @staticmethod
    def store_locally(path:Path, payload:str)->None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            f.write(payload)

    @staticmethod
    def restore_locally(path:Path)->bytes:
        with open(path, 'r') as f:
            payload = f.read()
            return payload
    
    @staticmethod
    def store_password_hash_locally(username:str, password:str):
        if not HelperUtilities.is_valid_password_format(password):
            raise BadInput

        hash_digest, salt_str = HelperUtilities.hash_password(password)

        path = Path('files/safe') / username / "password.txt"
        Safe.store_locally(path, f"{hash_digest}\n{salt_str}")
        return hash_digest, salt_str

    @staticmethod
    def restore_local_password_hash(username:str):
        path = Path('files/safe') / username / "password_hash.txt"
        try:
                payload = Safe.restore_locally(path)
                hash_digest, salt_str = payload.split("\n")
                return hash_digest, salt_str
        except FileNotFoundError:
            raise PasswordHashFileNotFound()

    @staticmethod
    def store_private_key_locally(username:str, password:str, salt_str:str, private_key_pem:bytes)->None:
        path = Path('files/safe') / username / "private_key.txt"
        key, iv = AES.derive_key_and_iv_from_two_texts(password, salt_str)
        cipher_text = AES.encrypt(private_key_pem.decode(), key, iv)
        Safe.store_locally(path, cipher_text)

    @staticmethod
    def restore_local_private_key(username:str, password:str, salt_str:str)->bytes:
        path = Path('files/safe') / username / "private_key.txt"
        try:
            cipher_text = Safe.restore_locally(path)
            key, iv = AES.derive_key_and_iv_from_two_texts(password, salt_str)
            private_key =  AES.decrypt(cipher_text, key, iv)
            return private_key.encode()
        except FileNotFoundError:
            raise PrivateKeyFileNotFound()
    
    @staticmethod
    def store_old_inbox_locally(username:str, password:str, salt_str:str, inbox:list[MessageBody], latest_read_message_id:int)->None:
        path = Path('files/safe') / username / "old_inbox.txt"
        key, iv = AES.derive_key_and_iv_from_two_texts(password, salt_str)
        payloads = [f"{message.sender_username},{message.receiver_username}{seperator1}{message.text}{seperator1}" for message in inbox]
        payloads.append(f"{latest_read_message_id}")
        cipher_text = AES.encrypt(seperator2.join(payloads), key, iv)
        Safe.store_locally(path, cipher_text)

    @staticmethod
    def restore_local_old_inbox(username:str, password:str, salt_str:str)->tuple[list[MessageBody, int]] | tuple[None, None]:
        path = Path('files/safe') / username / "old_inbox.txt"
        try:
            cipher_text = Safe.restore_locally(path)

            key, iv = AES.derive_key_and_iv_from_two_texts(password, salt_str)
            plain_text =  AES.decrypt(cipher_text, key, iv)
            
            payloads = plain_text.split(seperator2)
            latest_read_message = int(payloads.pop())
            inbox_message_fragments = [payload.split(seperator1) for payload in payloads]
            inbox_messages =  [MessageBody(message_fragment[0], message_fragment[1], message_fragment[2]) for message_fragment in inbox_message_fragments]
            return inbox_messages, latest_read_message
        except FileNotFoundError:
            return [], None

    @staticmethod
    def change_password(username:str, password:str, new_password:str, private_key_pem:bytes):
        _, new_salt_str = Safe.store_password_hash_locally(username, password)
        Safe.store_private_key_locally(username, new_password, new_salt_str, private_key_pem)
