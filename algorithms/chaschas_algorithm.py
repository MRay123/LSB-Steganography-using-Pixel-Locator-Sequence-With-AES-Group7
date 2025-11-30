import binascii
import pbkdf2
from Crypto.Cipher import ChaCha20

passwordSalt = b'\\`\xd6\xdaB\x03\xdd\xd4z\xb6p\xe8O\xf0\xa8\xc0'

def encrypt(raw, password):

    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(raw.encode('utf-8'))

    output = cipher.nonce + ciphertext

    return binascii.hexlify(output).decode('utf-8')


def decrypt(ciphertext_hex, password):
    
    ciphertext = binascii.unhexlify(ciphertext_hex.encode('utf-8'))

    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)

    nonce = ciphertext[:8]
    ct = ciphertext[8:]

    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ct)

    return plaintext.decode('utf-8')

