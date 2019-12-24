from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode
from base64 import b64decode
import json

def generate_aes_key():
    return Random.get_random_bytes(AES.key_size[0])

def encrypt_and_encode(src_str, AES_KEY):
    byte_str = json.dumps(src_str).encode()
    print(byte_str)
    NONCE = Random.get_random_bytes(AES.block_size-1)
    cipher = AES.new(AES_KEY, AES.MODE_OCB, NONCE)
    ciphertxt, MAC = cipher.encrypt_and_digest(byte_str)
    print('Hot here')
    return b64encode(ciphertxt).decode(), NONCE.decode('latin-1'), MAC.decode('latin-1')

def decode_and_decrypt(en_str, NONCE, MAC, AES_KEY):
    ciphertxt = b64decode(en_str)
    cipher = AES.new(AES_KEY, AES.MODE_OCB, NONCE.encode('latin-1'))
    src_str = cipher.decrypt_and_verify(ciphertxt, MAC.encode('latin-1')).decode()
    src_dict = json.loads(json.loads(src_str))
    return src_dict
