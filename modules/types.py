from typing import TypedDict

class User(TypedDict):
    username: str
    password: str
    salt: str
    public_key: str

class Signature(TypedDict):
    payload: str
    signature: bytes

class Message(TypedDict):
    key: bytes
    iv: bytes
    message_text: str
    sender_signature: Signature
    receiver_public_key_pem: bytes