from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm, InvalidKey


class RSA:
    @staticmethod
    def generate_pem_format_key_pair() -> tuple[bytes, bytes]:
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

    @staticmethod
    def is_valid_private_key(self, private_key:str):
        try:
            private_key = serialization.load_pem_private_key(
                private_key.encode(),
                password=None,
            )
            if isinstance(private_key, rsa.RSAPrivateKey):
                return private_key.key_size == 1024
            return False
        except (ValueError, UnsupportedAlgorithm, InvalidKey):
            return False

    @staticmethod
    def encrypt_with_public_key(public_pem: bytes, message: bytes) -> bytes:
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
    
    @staticmethod
    def sign_with_private_key(private_pem: bytes, payload: bytes)->bytes:
        private_key = serialization.load_pem_private_key(private_pem, password=None)

        signature = private_key.sign(
            payload,
            padding.PSS(  # Recommended for signatures
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return signature
    
    @staticmethod
    def is_signature_valid(public_pem: bytes, payload:str, signature: bytes)->bool:
        public_key = serialization.load_pem_public_key(public_pem)

        try:
            public_key.verify(
                signature,
                payload.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True  # Signature is valid
        except InvalidSignature:
            return False  # Signature is invalid