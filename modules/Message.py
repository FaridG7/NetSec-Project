import hashlib
import time
import random
from pathlib import Path

from modules.HelperUtilities import HelperUtilities
from modules.RSA import RSA
from modules.AES import AES
from modules.Signature import Signature
from modules.exceptions import ConflictError


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
        payload = f"{timestamp} Sender:{sender_username} Receiver:{receiver_username} Message_Hash:{message_hash}"
        return {
            'payload': payload,
            'signature': RSA.sign_with_private_key(sender_private_key_pem, payload)
        }

class MessageBody:
    sender_username: str
    receiver_username: str
    message_text: str

    def __init__(self, sender_username:str, receiver_username:str, message_text: str):
        self.sender_username = sender_username
        self.receiver_username = receiver_username
        self.message_text = message_text

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
        filename = HelperUtilities.generate_random_text(random.randint(10, 20))
        path = Path('files/messages') / f"{filename}.txt"
        with open(path, 'w') as f:
            for message in messages:
                tagged_key_and_iv = str(message.key) + str(message.iv) + b"::OK"

                encrypted_key = RSA.encrypt_with_public_key(message.receiver_public_key_pem, tagged_key_and_iv)
                encrypted_signature = RSA.encrypt_with_public_key(message.receiver_public_key_pem, str(message.signature))
                cipher_text = AES.encrypt(message.message_text, message['key'], message['iv'])

                f.write('------------------------------Begin Message------------------------------')
                f.write(f"\n{encrypted_key}\n{encrypted_signature}\n{cipher_text}\n")
                f.write('------------------------------End Message------------------------------')

    @staticmethod
    def send_messages(messages:list["Message"], users_count:int)->None:
        messages_max_length = max(len(message['message_text']) for message in messages)
        messages_min_length = min(len(message['message_text']) for message in messages)

        fake_messages = Message.generate_fake_messages(messages_min_length, messages_max_length, users_count - len(messages))
        
        real_and_fake_messages = random.shuffle(messages + fake_messages)
        
        Message.dump_messages_to_file(real_and_fake_messages)
