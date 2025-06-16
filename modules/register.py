import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from exceptions import ConflictError

def load_users(path):
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except json.JSONDecodeError:
            return []
    else:
        return []

def check_for_duplicate_user_names(users, username):
    if any(u['username'] == username for u in users):
        raise ConflictError
    
def generate_pem_format_key_pair():
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
    return private_pem, public_pem

def dump_username_to_file(path, users):
    with open(path, 'w') as f:
        json.dump(users, f, indent=2)


def register_user(username: str)->str:
    path = Path('files') / 'users.json'
    users = load_users()

    check_for_duplicate_user_names(users, username)
    
    private_pem, public_pem = generate_pem_format_key_pair()

    users.append({"username": username, "public_key": public_pem.decode()})

    dump_username_to_file(path, users)

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