from pathlib import Path

from modules.AES import AES
from modules.HelperUtilities import HelperUtilities
from modules.Message import MessageBody
from modules.exceptions import BadInput, PasswordHashFileNotFound, PrivateKeyFileNotFound


seperator1 = "-------------------------------------------------------------------------------------------------------\n"
seperator2 = ";;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;\n"

class Safe:
    @staticmethod
    def store_locally(path:Path, payload:bytes)->None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            f.write(payload)

    @staticmethod
    def restore_locally(path:Path)->bytes:
        with open(path, 'rb') as f:
            payload = f.read()
            return payload
    
    @staticmethod
    def store_password_hash_locally(username:str, password:str):
        if not HelperUtilities.is_valid_password_format(password):
            raise BadInput

        hash_digest, salt_str = HelperUtilities.hash_password(password)

        path = Path('files/safe') / username / "password_hash.enc"
        Safe.store_locally(path, hash_digest + salt_str)

        return hash_digest, salt_str

    @staticmethod
    def restore_local_password_hash(username:str):
        path = Path('files/safe') / username / "password_hash.enc"
        try:
            payload = Safe.restore_locally(path)
            return payload[:32], payload[32:]
        except FileNotFoundError:
            raise PasswordHashFileNotFound()

    @staticmethod
    def store_private_key_locally(username:str, password:str, salt:bytes, private_key_pem:bytes)->None:
        path = Path('files/safe') / username / "private_key.enc"
        key, iv = AES.derive_key_and_iv_from_two_texts(password, salt)
        cipher_text = AES.encrypt(private_key_pem.decode(), key, iv)
        Safe.store_locally(path, cipher_text)

    @staticmethod
    def restore_local_private_key(username:str, password:str, salt:bytes)->bytes:
        path = Path('files/safe') / username / "private_key.enc"
        try:
            cipher_text = Safe.restore_locally(path)
            key, iv = AES.derive_key_and_iv_from_two_texts(password, salt)
            private_key =  AES.decrypt(cipher_text, key, iv)
            return private_key.encode()
        except FileNotFoundError:
            raise PrivateKeyFileNotFound()
    
    @staticmethod
    def store_old_inbox_locally(username:str, password:str, salt:bytes, inbox:list[MessageBody], latest_read_message_id:int)->None:
        path = Path('files/safe') / username / "old_inbox.enc"

        key, iv = AES.derive_key_and_iv_from_two_texts(password, salt)

        payloads = [f"{message.sender_username},{message.receiver_username}{seperator1}{message.text}{seperator1}" for message in inbox]
        payloads.append(f"{latest_read_message_id}")
        
        cipher_text = AES.encrypt(seperator2.join(payloads), key, iv)
        
        Safe.store_locally(path, cipher_text)

    @staticmethod
    def restore_local_old_inbox(username:str, password:str, salt:bytes)->(tuple[list[MessageBody], int]):
        path = Path('files/safe') / username / "old_inbox.enc"
        try:
            cipher_text = Safe.restore_locally(path)

            key, iv = AES.derive_key_and_iv_from_two_texts(password, salt)
            plain_text =  AES.decrypt(cipher_text, key, iv)
            
            payloads = plain_text.split(seperator2)

            latest_read_message = int(payloads.pop())

            inbox_message_fragments = [payload.split(seperator1) for payload in payloads]
            inbox_messages =  [MessageBody(message_fragment[0], message_fragment[1], message_fragment[2]) for message_fragment in inbox_message_fragments]
            
            return inbox_messages, latest_read_message
        except FileNotFoundError:
            return [], 0

    @staticmethod
    def change_password(username:str, password:str, new_password:str, private_key_pem:bytes):
        _, new_salt_str = Safe.store_password_hash_locally(username, password)
        Safe.store_private_key_locally(username, new_password, new_salt_str, private_key_pem)
