import hashlib
from modules.RSA import RSA

class Signature:
    payload: str
    signed_payload: bytes

    def __init__(self, payload:str, private_key_pem:bytes):
        self.payload = payload
        self.signed_payload = RSA.sign_with_private_key(private_key_pem, hashlib.sha256(payload).hexdigest())

    def __str__(self):
        return f"payload:{self.payload}\nsignature:{self.signed_payload}"
