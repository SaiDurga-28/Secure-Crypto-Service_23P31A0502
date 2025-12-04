# app.py
from fastapi import FastAPI, HTTPException
import base64, os, time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from totp_utils import generate_totp_code, verify_totp_code

app = FastAPI()

SEED_PATH = "data/seed.txt"
PRIVATE_KEY_PATH = "student_private.pem"

@app.post("/decrypt-seed")
def decrypt_seed_api(payload: dict):
    if "encrypted_seed" not in payload:
        raise HTTPException(status_code=400, detail="Missing encrypted_seed")

    encrypted_b64 = payload["encrypted_seed"]

    # load private key
    try:
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except Exception:
        raise HTTPException(status_code=500, detail="Private key load failed")

    try:
        cipher_bytes = base64.b64decode(encrypted_b64)
        pt = private_key.decrypt(
            cipher_bytes,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        seed_hex = pt.decode().strip()

        # Validate
        if len(seed_hex) != 64 or not all(c in "0123456789abcdef" for c in seed_hex.lower()):
            raise ValueError("Invalid seed format")

        os.makedirs("data", exist_ok=True)
        with open(SEED_PATH, "w") as f:
            f.write(seed_hex)

    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception:
        raise HTTPException(status_code=500, detail="Decryption failed")

    return {"status": "ok"}


@app.get("/generate-2fa")
def generate_2fa():
    if not os.path.exists(SEED_PATH):
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    seed_hex = open(SEED_PATH).read().strip()
    code = generate_totp_code(seed_hex)
    current = int(time.time())
    valid_for = 30 - (current % 30)
    return {"code": code, "valid_for": valid_for}


@app.post("/verify-2fa")
def verify_2fa(payload: dict):
    if "code" not in payload:
        raise HTTPException(status_code=400, detail="Missing code")
    if not os.path.exists(SEED_PATH):
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    seed_hex = open(SEED_PATH).read().strip()
    code = payload["code"]
    is_valid = verify_totp_code(seed_hex, code, valid_window=1)
    return {"valid": bool(is_valid)}