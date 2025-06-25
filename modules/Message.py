import hashlib
import time
from modules.AES import AES
from modules.Signature import Signature


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
            'signature': self.sign_with_private_key(sender_private_key_pem, payload)
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