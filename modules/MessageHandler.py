
from pathlib import Path
import random
import secrets
import string
from modules.RSA import RSA
from modules.AES import AES
from modules.types import Message, Signature

class MessageHandler(AES, RSA):
    def create_message_object(self, message_text:str, sender_signature:Signature, reciever_public_key_pem:bytes):
        key , iv = self.generate_random_key_and_iv()
        return{
            'key':key,
            'iv':iv,
            'message_text':message_text,
            'sender_signature':sender_signature,
            'reciever_public_key_pem':reciever_public_key_pem
        }
    
    def generate_random_text(length:int):
        chars = string.ascii_letters + string.digits
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def generate_fake_messages(self, messages_min_length:int, messages_max_length:int, sender_signature:Signature, reciever_public_key_pem:bytes, count:int):
        fake_messages = []
        for _ in range(count):
            random_text = self.generate_random_text(random.randint(messages_min_length, messages_max_length))

            msg = self.create_message_object(random_text, sender_signature, reciever_public_key_pem)
            fake_messages.append(msg)

    def dump_messages_to_file(self, messages:int):
        filename = self.generate_random_text(random.randint(10, 20))
        path = Path('files/messages') / f"{filename}.txt"
        with open(path) as f:
            for message in messages:
                tagged_key_and_iv = message['key'] + message['iv'] + b"::OK"
                encrypted_key = self.encrypt_with_public_key(message['reciever_public_key_pem'], tagged_key_and_iv)
                cipher_text = self.encrypt(message['message_text'], message['key'], message['iv'])
                f.write('------------------------------Begin Message------------------------------')
                f.write(encrypted_key)
                f.write(message['sender_signature']['payload'])
                f.write(message['sender_signature']['signature'])
                f.write(cipher_text)
                f.write('------------------------------End Message------------------------------')

    def send_messages(self, messages:list[Message], sender_signature:Signature, reciever_public_key_pem:bytes, users_count:int)->None:
        messages_max_length = max(len(message['message_text']) for message in messages)
        messages_min_length = min(len(message['message_text']) for message in messages)
        fake_messages = self.generate_fake_messages(messages_min_length, messages_max_length, sender_signature, reciever_public_key_pem, users_count - len(messages))
        real_and_fake_messages = random.shuffle(messages + fake_messages)
        self.dump_messages_to_file(real_and_fake_messages)
