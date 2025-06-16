import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from exceptions import ConflictError

def register(username: str)->str:
    path = Path('files') / 'users.json'
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        try:
            with open(path) as f:
                users = json.load(f)
        except json.JSONDecodeError:
            users = []
    else:
        users = []

    if any(u['username'] == username for u in users):
        raise ConflictError
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # or use a password
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    users.append({"username": username, "public_key": public_pem.decode()})

    # with open(path, 'w') as f:
    #     json.dump(users, f, indent=2)

    return {
    "username": username,
    "public_key": public_pem.decode(),
    "private_key": private_pem.decode(),
    "note": "Save your private key somewhere safe. It won't be stored."
}



# try:
#     result = register('test4')
#     print(result['private_key'])
# except ConflictError:
#     print('Username already exists.')