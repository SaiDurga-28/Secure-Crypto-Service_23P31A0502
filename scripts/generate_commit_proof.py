#!/usr/bin/env python3
# scripts/generate_commit_proof.py
import sys
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

# Paths (adjust if your files are in different places)
STUDENT_PRIV_PEM = Path("student_private.pem")
INSTRUCTOR_PUB_PEM = Path("instructor_public.pem")

def load_private_key(path: Path):
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=None)

def load_public_key(path: Path):
    data = path.read_bytes()
    return serialization.load_pem_public_key(data)

def sign_message(message: str, private_key) -> bytes:
    """
    Sign ASCII message string using RSA-PSS with SHA-256.
    - message: ASCII string (40-char commit hash). IMPORTANT: sign the ASCII string bytes.
    """
    msg_bytes = message.encode("utf-8")   # ASCII/UTF-8 bytes
    signature = private_key.sign(
        msg_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH  # Maximum salt length
        ),
        hashes.SHA256()
    )
    return signature

def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    """
    Encrypt bytes with RSA/OAEP using SHA-256.
    """
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def main():
    if len(sys.argv) >= 2:
        commit_hash = sys.argv[1].strip()
    else:
        print("Usage: generate_commit_proof.py <commit_hash>", file=sys.stderr)
        return 2

    if len(commit_hash) != 40:
        print("Error: commit hash must be 40 hex chars", file=sys.stderr)
        return 3

    priv = load_private_key(STUDENT_PRIV_PEM)
    pub = load_public_key(INSTRUCTOR_PUB_PEM)

    sig = sign_message(commit_hash, priv)              # bytes
    cipher = encrypt_with_public_key(sig, pub)        # bytes
    b64 = base64.b64encode(cipher).decode("utf-8")    # string

    # Print outputs exactly as required:
    print("COMMIT_HASH:", commit_hash)
    print("ENCRYPTED_COMMIT_SIGNATURE_BASE64:")   # evaluator expects a single-line base64 string
    print(b64)                                   # must be single-line
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
