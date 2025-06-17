from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from modules.types import Signature

class RSA:
    def generate_pem_format_key_pair(self) -> tuple[bytes, bytes]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return private_pem, public_pem

    def encrypt_with_public_key(self, public_pem: bytes, message: bytes) -> bytes:
        public_key = serialization.load_pem_public_key(public_pem)

        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(  # Recommended padding
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    def sign_with_private_key(self, private_pem: bytes, message: bytes) -> Signature:
        private_key = serialization.load_pem_private_key(private_pem, password=None)

        signature = private_key.sign(
            message,
            padding.PSS(  # Recommended for signatures
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {
            'payload':message,
            'signature': signature
        }
