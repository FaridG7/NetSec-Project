import hashlib
from dataclasses import dataclass

from modules.RSA import RSA

@dataclass(frozen=True)
class Signature:
    payload: str
    signed_payload: bytes

    def from_dependencies(cls, payload:str, private_key_pem:bytes):
        return cls(
            payload=payload,
            signed_payload=RSA.sign_with_private_key(private_key_pem, hashlib.sha256(payload.encode()).hexdigest())
        )

    def __str__(self):
        return f"(payload:{self.payload}\nsignature:{self.signed_payload})"
