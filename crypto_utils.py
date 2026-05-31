from __future__ import annotations

import base64
import hashlib
import os
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DH_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
    "7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899F"
    "A5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C"
    "62F356208552BB9ED529077096966D670C354E4ABC9804F174"
    "6C08CA237327FFFFFFFFFFFFFFFF"
)
DH_P = int(DH_P_HEX, 16)
DH_G = 2


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def random_aes_key() -> bytes:
    return os.urandom(32)


def aes_encrypt_text(text: str, key: bytes) -> str:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(text.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return b64e(iv + ct)


def aes_decrypt_text(payload: str, key: bytes) -> str:
    raw = b64d(payload)
    iv = raw[:16]
    ct = raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()
    return data.decode("utf-8")


def ensure_rsa_keys(private_path: str, public_path: str) -> tuple[bytes, bytes]:
    if os.path.exists(private_path) and os.path.exists(public_path):
        with open(private_path, "rb") as f:
            private_pem = f.read()
        with open(public_path, "rb") as f:
            public_pem = f.read()
        return private_pem, public_pem
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(private_path, "wb") as f:
        f.write(private_pem)
    with open(public_path, "wb") as f:
        f.write(public_pem)
    return private_pem, public_pem


def rsa_encrypt_aes_key(public_pem: bytes, aes_key: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_pem, backend=default_backend())
    return public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt_aes_key(private_pem: bytes, payload: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(private_pem, password=None, backend=default_backend())
    return private_key.decrypt(
        payload,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def dh_make_private() -> int:
    return secrets.randbelow(DH_P - 3) + 2


def dh_make_public(private_value: int) -> int:
    return pow(DH_G, private_value, DH_P)


def dh_derive_aes_key(peer_public: int, private_value: int) -> bytes:
    shared = pow(peer_public, private_value, DH_P)
    shared_bytes = shared.to_bytes((shared.bit_length() + 7) // 8, "big")
    return hashlib.sha256(shared_bytes).digest()
