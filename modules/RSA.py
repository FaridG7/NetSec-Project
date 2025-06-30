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
    def encrypt_with_public_key(public_pem: bytes, message: str) -> bytes:
        public_key = serialization.load_pem_public_key(public_pem)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError("Provided public key is not an RSA public key.")

        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(  # Recommended padding
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    @staticmethod
    def decrypt_with_private_key(privat_pem: bytes, cipher_text: bytes) -> str:
        private_key = serialization.load_pem_private_key(privat_pem, password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError("Provided private key is not an RSA private key.")

        plain_text = private_key.decrypt(
            cipher_text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return plain_text.decode()

    @staticmethod
    def sign_with_private_key(private_pem: bytes, payload: str)->bytes:
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise TypeError("Provided private key is not an RSA private key.")

        signature = private_key.sign(
            payload.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return signature
    
    @staticmethod
    def is_signature_valid(public_pem: bytes, payload:str, signature: bytes)->bool:
        public_key = serialization.load_pem_public_key(public_pem)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError("Provided public key is not an RSA public key.")

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
            return True
        except InvalidSignature:
            return False