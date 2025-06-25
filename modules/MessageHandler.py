
from pathlib import Path
import random
import secrets
import string

from modules.RSA import RSA
from modules.AES import AES
from modules.Message import Message


class MessageHandler(AES, RSA):
    def generate_random_text(length:int):
        chars = string.ascii_letters + string.digits
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def generate_fake_messages(self, messages_min_length:int, messages_max_length:int, count:int):
        fake_messages = []
        for _ in range(count):
            dummy_private_key_pem, dummy_public_key_pem = self.generate_pem_format_key_pair()
            random_text = self.generate_random_text(random.randint(messages_min_length, messages_max_length))
            msg = Message(random_text,dummy_private_key_pem, "dummy", "dummy", dummy_public_key_pem)
            fake_messages.append(msg)

    def dump_messages_to_file(self, messages:list[Message]):
        filename = self.generate_random_text(random.randint(10, 20))
        path = Path('files/messages') / f"{filename}.txt"
        with open(path, 'w') as f:
            for message in messages:
                tagged_key_and_iv = str(message.key) + str(message.iv) + b"::OK"

                encrypted_key = self.encrypt_with_public_key(message.receiver_public_key_pem, tagged_key_and_iv)
                encrypted_signature = self.encrypt_with_public_key(message.receiver_public_key_pem, str(message.signature))
                cipher_text = self.encrypt(message.message_text, message['key'], message['iv'])

                f.write('------------------------------Begin Message------------------------------')
                f.write(f"\n{encrypted_key}\n{encrypted_signature}\n{cipher_text}\n")
                f.write('------------------------------End Message------------------------------')

    def send_messages(self, messages:list[Message], users_count:int)->None:
        messages_max_length = max(len(message['message_text']) for message in messages)
        messages_min_length = min(len(message['message_text']) for message in messages)

        fake_messages = self.generate_fake_messages(messages_min_length, messages_max_length, users_count - len(messages))
        
        real_and_fake_messages = random.shuffle(messages + fake_messages)
        
        self.dump_messages_to_file(real_and_fake_messages)
