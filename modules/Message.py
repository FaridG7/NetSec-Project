import hashlib
import time
import random
from pathlib import Path

from modules.HelperUtilities import HelperUtilities
from modules.RSA import RSA
from modules.AES import AES
from modules.Safe import Safe
from modules.Signature import Signature
from modules.User import User


class MessageHeader:
    key: bytes
    iv: bytes
    receiver_public_key_pem: bytes
    signature: Signature

    def __init__(self, message_text:str, sender_private_key_pem: bytes, sender_username:str, receiver_username:str, receiver_public_key_pem: bytes):
        self.key , self.iv = AES.generate_random_key_and_iv()
        self.receiver_public_key_pem = receiver_public_key_pem
        self.signature = self.create_signature_for_message(message_text, sender_private_key_pem, sender_username, receiver_username)
    
    def create_signature_for_message(self, message_text:str, sender_private_key_pem:bytes, sender_username:str, receiver_username:str)->Signature:
        timestamp = time.asctime(time.localtime())
        message_hash = hashlib.sha256(message_text).hexdigest()
        payload = f"{timestamp},Sender:{sender_username},Receiver:{receiver_username},Message_Hash:{message_hash}"
        return {
            'payload': payload,
            'signature': RSA.sign_with_private_key(sender_private_key_pem, payload)
        }

class MessageBody:
    sender_username: str
    receiver_username: str
    text: str

    def __init__(self, sender_username:str, receiver_username:str, text: str):
        self.sender_username = sender_username
        self.receiver_username = receiver_username
        self.text = text

class Message(MessageHeader, MessageBody):
    def __init__(self, message_text:str, sender_private_key_pem: bytes, sender_username:str, receiver_username:str, receiver_public_key_pem: bytes):
        MessageHeader.__init__(self, message_text, sender_private_key_pem, sender_username, receiver_username, receiver_public_key_pem )
        MessageBody.__init__(self, sender_username, receiver_username, message_text)
    
    @staticmethod
    def generate_fake_messages(messages_min_length:int, messages_max_length:int, count:int):
        fake_messages = []
        for _ in range(count):
            dummy_private_key_pem, dummy_public_key_pem = RSA.generate_pem_format_key_pair()
            random_text = HelperUtilities.generate_random_text(random.randint(messages_min_length, messages_max_length))
            msg = Message(random_text,dummy_private_key_pem, "dummy", "dummy", dummy_public_key_pem)
            fake_messages.append(msg)
    
    @staticmethod
    def dump_messages_to_file(messages:list["Message"]):
        latest_message_file_id = HelperUtilities.find_latest_message_id()
        messages_file_id = latest_message_file_id + 1
        path = Path('files/messages') / f"msg_{messages_file_id}.txt"
        with open(path, 'w') as f:
            border = '------------------------------Message Border------------------------------\n'
            for message in messages:
                tagged_key_and_iv = str(message.key) + str(message.iv) + "::OK"

                encrypted_key = RSA.encrypt_with_public_key(message.receiver_public_key_pem, tagged_key_and_iv)
                encrypted_signature = AES.encrypt(str(message.signature), message['key'], message['iv'])
                cipher_text = AES.encrypt(message.text, message['key'], message['iv'])

                f.write(f"{encrypted_key}\n{encrypted_signature}\n{cipher_text}\n")
                f.write(border)

    @staticmethod
    def send_messages(messages:list["Message"], users_count:int)->None:
        messages_max_length = max(len(message['message_text']) for message in messages)
        messages_min_length = min(len(message['message_text']) for message in messages)

        fake_messages = Message.generate_fake_messages(messages_min_length, messages_max_length, users_count - len(messages))
        
        real_and_fake_messages = random.shuffle(messages + fake_messages)
        
        Message.dump_messages_to_file(real_and_fake_messages)


    @staticmethod
    def decrypt_and_validate_key(private_key_pem:bytes, encrypted_key:str):
        try:
            decrypted_key = RSA.decrypt_with_private_key(private_key_pem, encrypted_key)

            if decrypted_key.endswith("::OK"):
                return decrypted_key[:16], decrypted_key[16:-len("::OK")]
            else:
                return None, None
        except Exception:
            return None, None

    @staticmethod
    def export_message(text:str, private_key_pem:bytes, username_public_key_map:dict[str, bytes])->MessageBody | None:
        border = '------------------------------Message Border------------------------------\n'
        encrypted_message_texts = text.split(border)

        for encrypted_message_text in encrypted_message_texts:
            encrypted_key, encrypted_signature, cipher_text = encrypted_message_text.split('\n')
            decrypted_key, decrypted_iv = Message.decrypt_and_validate_key(private_key_pem, encrypted_key)
            if decrypted_key and decrypted_iv:
                signature_payload, signature_signed_payload = [ value for label, value in [ item.split(":")for item in AES.decrypt(encrypted_signature, decrypted_key, decrypted_iv).split("\n") ] ]
                sender_username, receiver_username, _ = [ value for label, value in [ item.split(':') for item in signature_payload.split(',')[1:] ] ]
                text = AES.decrypt(cipher_text, decrypted_key, decrypted_iv)

                if RSA.is_signature_valid(username_public_key_map[sender_username], signature_payload, signature_signed_payload):
                    return MessageBody(sender_username, receiver_username, text)
        return None

    @staticmethod
    def load_inbox(username:str, password:str, salt_str:str, private_key_pem:bytes, users:list[User])->list["MessageBody"]:
        old_inbox, latest_read_message_file_id = Safe.restore_local_old_inbox(username, password, salt_str)

        latest_message_file_id = HelperUtilities.find_latest_message_id()

        username_public_key_map = {user['username']: user['public_key_pem'] for user in users}

        directory_path = Path('files/messages')
        for messages_file_id in [f"{id}" for id in range(latest_read_message_file_id, latest_message_file_id)]:
            path = directory_path / f"msg_{messages_file_id}.txt"
            with open(path, 'r') as f:
                message = Message.export_message(f.read(), private_key_pem, username_public_key_map)
                if message:
                    old_inbox.append(message)
        
        return old_inbox