# ecc_utils.py
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
from typing import Tuple

# Use a standard curve
CURVE = ec.SECP256R1()  # aka prime256v1

def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Returns (private_pem, public_pem) as bytes (PEM encoded).
    Save these to files or keep in memory.
    """
    priv = ec.generate_private_key(CURVE)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem

def load_private_key(priv_pem: bytes):
    return serialization.load_pem_private_key(priv_pem, password=None)

def load_public_key(pub_pem: bytes):
    return serialization.load_pem_public_key(pub_pem)

def _derive_aes_key(shared_key: bytes, info: bytes = b"ecies-aes-key", length=32) -> bytes:
    # Derive a symmetric key from ECDH shared secret using HKDF-SHA256
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(shared_key)

def encrypt_with_recipient_pub(recipient_pub_pem: bytes, plaintext: bytes) -> bytes:
    """
    ECIES-style encrypt:
    - generate ephemeral keypair E
    - ECDH between E.private and recipient.public => shared secret
    - HKDF -> AES-GCM key
    - AES-GCM encrypt plaintext
    Returns a single base64 blob containing: ephem_pub_pem || nonce || ciphertext || tag
    """
    recipient_pub = load_public_key(recipient_pub_pem)
    # Ephemeral key
    eph_priv = ec.generate_private_key(CURVE)
    eph_pub = eph_priv.public_key()
    # ECDH
    shared = eph_priv.exchange(ec.ECDH(), recipient_pub)  # bytes
    aes_key = _derive_aes_key(shared)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)  # includes tag at end for AESGCM
    # Pack ephemeral public key (PEM), nonce, and ciphertext together
    eph_pub_pem = eph_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    blob = b"-----BEGIN EPH-PUB-----\n" + base64.b64encode(eph_pub_pem) + b"\n-----END EPH-PUB-----\n" + base64.b64encode(nonce) + b"::" + base64.b64encode(ct)
    # base64 again to ensure it's ascii-safe for embedding
    return base64.b64encode(blob)

def decrypt_with_own_priv(my_priv_pem: bytes, b64_blob: bytes) -> bytes:
    """
    Reverse of encrypt_with_recipient_pub.
    Input: base64 blob produced by encrypt_with_recipient_pub.
    Returns plaintext bytes.
    """
    blob = base64.b64decode(b64_blob)
    # split into parts: ephem marker, base64 eph_pem, base64 nonce :: base64 ct
    try:
        start = b"-----BEGIN EPH-PUB-----\n"
        end = b"\n-----END EPH-PUB-----\n"
        i1 = blob.index(start) + len(start)
        i2 = blob.index(end, i1)
    except ValueError:
        raise ValueError("Malformed ECC blob")
    eph_pub_b64 = blob[i1:i2]
    rest = blob[i2+len(end):]
    nonce_b64, ct_b64 = rest.split(b"::", 1)
    eph_pub_pem = base64.b64decode(eph_pub_b64)
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)

    my_priv = load_private_key(my_priv_pem)
    eph_pub = load_public_key(eph_pub_pem)
    shared = my_priv.exchange(ec.ECDH(), eph_pub)
    aes_key = _derive_aes_key(shared)
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return plaintext

# High-level wrappers expected by main.py
def encrypt(message: str) -> str:
    # Load recipient's public key from file
    with open("ecc_public.pem", "rb") as f:
        pub = f.read()
    enc = encrypt_with_recipient_pub(pub, message.encode())
    return enc.decode()

def decrypt(b64_blob: str) -> str:
    # Load your private key from file
    with open("ecc_private.pem", "rb") as f:
        priv = f.read()
    dec = decrypt_with_own_priv(priv, b64_blob.encode())
    return dec.decode()