from Crypto.Cipher import DES3
import binascii
import pbkdf2


passwordSalt = b'\\`\xd6\xdaB\x03\xdd\xd4z\xb6p\xe8O\xf0\xa8\xc0'
iv = 11357323082506326930  


def _make_counter(iv_int):
    while True:
        yield iv_int.to_bytes(16, "big")
        iv_int = (iv_int + 1) & ((1 << 128) - 1)


def encrypt(raw, password):
    key = pbkdf2.PBKDF2(password, passwordSalt).read(24)
    key = DES3.adjust_key_parity(key)

    cipher = DES3.new(key, DES3.MODE_ECB)

    counter = _make_counter(iv)
    raw_bytes = raw.encode("utf-8")
    encrypted = b""

    for i in range(0, len(raw_bytes), 8):
        block = raw_bytes[i:i+8]
        keystream = cipher.encrypt(next(counter)[:8])
        encrypted += bytes(a ^ b for a, b in zip(block, keystream))

    return binascii.hexlify(encrypted).decode("utf-8")


def decrypt(cipherText, password):
    cipher_bytes = binascii.unhexlify(cipherText.encode("utf-8"))

    key = pbkdf2.PBKDF2(password, passwordSalt).read(24)
    key = DES3.adjust_key_parity(key)

    cipher = DES3.new(key, DES3.MODE_ECB)

    counter = _make_counter(iv)
    decrypted = b""

    for i in range(0, len(cipher_bytes), 8):
        block = cipher_bytes[i:i+8]
        keystream = cipher.encrypt(next(counter)[:8])
        decrypted += bytes(a ^ b for a, b in zip(block, keystream))

    return decrypted.decode("utf-8")