import hashlib
from modules.RSA import RSA

class Signature(RSA):
    payload: str
    signature: bytes

    def __init__(self, payload:str, private_key_pem:bytes):
        self.payload = payload
        self.signature = self.create_signature(payload, private_key_pem)

    def create_signature(self, payload:str, private_key_pem:bytes):
        payload_hash_digest = hashlib.sha256(payload).hexdigest()
        return self.sign_with_private_key(private_key_pem, payload_hash_digest)
    
    def __str__(self):
        return f"payload:{self.payload}\nsignature:{self.signature}"

    @staticmethod
    def is_signature_valid(signature:"Signature"):
        payload_hash_digest = hashlib.sha256(signature.payload).hexdigest()
        return payload_hash_digest == signature.signature