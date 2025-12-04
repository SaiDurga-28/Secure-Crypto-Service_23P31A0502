# decrypt_seed.py
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

ENCRYPTED_B64 = Path("encrypted_seed.txt")
ENCRYPTED_BIN = Path("encrypted_seed.bin")
OUT = Path("decrypted_seed.txt")
PRIV_PATH = Path("student_private.pem")

# Load ciphertext (try base64 file first, then raw bytes)
if ENCRYPTED_B64.exists():
    b64 = ENCRYPTED_B64.read_text().strip()
    try:
        cipher = base64.b64decode(b64)
    except Exception as e:
        raise SystemExit(f"Failed to base64-decode encrypted_seed.b64: {e}")
elif ENCRYPTED_BIN.exists():
    cipher = ENCRYPTED_BIN.read_bytes()
else:
    raise SystemExit("No encrypted_seed.b64 or encrypted_seed.bin found. Run request step first.")

# Load private key
priv_data = PRIV_PATH.read_bytes()
private_key = serialization.load_pem_private_key(priv_data, password=None)

# Try decryption with OAEP+SHA256, fallback to OAEP+SHA1
def try_decrypt(ciphertext, mgf_hash, algo_hash):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=mgf_hash),
            algorithm=algo_hash,
            label=None
        )
    )

for label in ("OAEP-SHA256", "OAEP-SHA1"):
    try:
        if label == "OAEP-SHA256":
            pt = try_decrypt(cipher, hashes.SHA256(), hashes.SHA256())
        else:
            pt = try_decrypt(cipher, hashes.SHA1(), hashes.SHA1())
        OUT.write_bytes(pt)
        print(f"Decryption successful with {label}. Saved to {OUT}")
        print("Decrypted (utf-8) preview:")
        try:
            print(pt.decode())
        except Exception:
            print("<binary data — not utf-8 printable>")
        break
    except Exception as e:
        print(f"{label} failed: {e}")
else:
    raise SystemExit("Decryption failed with both OAEP-SHA256 and OAEP-SHA1. Check encryption scheme.")
