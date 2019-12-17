from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode
from base64 import b64decode

def generate_aes_key():
    return Random.get_random_bytes(AES.key_size[0])

def encrypt_str(src_str, AES_KEY):
    NONCE = Random.get_random_bytes(AES.block_size-1)
    cipher = AES.new(AES_KEY, AES.MODE_OCB, NONCE)
    ciphertxt, MAC = cipher.encrypt_and_digest(src_str)
    return b64encode(ciphertxt).decode(), NONCE.decode('latin-1'), MAC.decode('latin-1')

def decrypt_str(en_str, NONCE, MAC, AES_KEY):
    ciphertxt = b64decode(en_str)
    cipher = AES.new(AES_KEY, AES.MODE_OCB, NONCE.encode('latin-1'))
    source_string = cipher.decrypt_and_verify(ciphertxt, MAC.encode('latin-1')).decode()
    return source_string
