import hashlib
from dataclasses import dataclass

from modules.RSA import RSA

@dataclass(frozen=True)
class Signature:
    payload: str
    signed_payload: bytes

    @classmethod
    def from_dependencies(cls, payload:str, private_key_pem:bytes):
        return cls(
            payload=payload,
            signed_payload=RSA.sign_with_private_key(private_key_pem, hashlib.sha256(payload.encode()).hexdigest())
        )
    
    def to_dict(self)->dict[str, str]:
        return {
            "payload": self.payload,
            "signed_payload": self.signed_payload.hex()
        }

    @staticmethod
    def from_dict(data):
        return Signature(
            payload=data["payload"],
            signed_payload=bytes.fromhex(data["signed_payload"]) 
        )

    def __str__(self):
        return f"(payload:{self.payload}\nsignature:{self.signed_payload.hex()})"

    def is_signature_valid(self, public_key_pem:bytes)->bool:
        return RSA.is_signature_valid(public_key_pem, hashlib.sha256(self.payload.encode()).hexdigest(), self.signed_payload)
