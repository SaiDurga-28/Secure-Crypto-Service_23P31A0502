# app.py
from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse
import base64
import os
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from totp_utils import generate_totp_code, verify_totp_code

app = FastAPI()

# Use container paths required by grader
SEED_PATH = "/data/seed.txt"
PRIVATE_KEY_PATH = "/app/student_private.pem"


def json_error(message: str, status_code: int = 500):
    return JSONResponse(status_code=status_code, content={"error": message})


@app.post("/decrypt-seed")
def decrypt_seed_api(payload: dict):
    if "encrypted_seed" not in payload:
        return json_error("Missing encrypted_seed", 400)

    encrypted_b64 = payload["encrypted_seed"]

    # load private key
    try:
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        return json_error("Private key missing", 500)
    except Exception:
        return json_error("Private key load failed", 500)

    try:
        cipher_bytes = base64.b64decode(encrypted_b64)
    except Exception:
        return json_error("Invalid base64 encrypted_seed", 400)

    try:
        pt = private_key.decrypt(
            cipher_bytes,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception:
        return json_error("Decryption failed", 500)

    try:
        seed_hex = pt.decode("utf-8").strip()
    except Exception:
        # maybe binary 32 bytes -> hex
        if len(pt) == 32:
            seed_hex = pt.hex()
        else:
            return json_error("Decrypted seed not valid UTF-8", 500)

    # Validate: 64 hex characters
    if len(seed_hex) != 64 or not all(c in "0123456789abcdef" for c in seed_hex.lower()):
        return json_error("Invalid seed format", 400)

    # Persist to /data/seed.txt
    try:
        os.makedirs(os.path.dirname(SEED_PATH), exist_ok=True)
        # write with no extra whitespace
        with open(SEED_PATH, "w", encoding="utf-8") as f:
            f.write(seed_hex)
        try:
            os.chmod(SEED_PATH, 0o600)
        except Exception:
            # chmod may fail on some platforms; ignore but continue
            pass
    except Exception:
        return json_error("Failed to save seed", 500)

    return {"status": "ok"}


@app.get("/generate-2fa")
def generate_2fa():
    if not os.path.exists(SEED_PATH):
        return json_error("Seed not decrypted yet", 500)

    try:
        with open(SEED_PATH, "r", encoding="utf-8") as f:
            seed_hex = f.read().strip()
    except Exception:
        return json_error("Failed to read seed", 500)

    # generate totp
    try:
        code = generate_totp_code(seed_hex)
    except Exception:
        return json_error("Seed invalid", 500)

    current = int(time.time())
    valid_for = 30 - (current % 30)
    return {"code": code, "valid_for": valid_for}


@app.post("/verify-2fa")
def verify_2fa(payload: dict):
    if "code" not in payload:
        return json_error("Missing code", 400)
    if not os.path.exists(SEED_PATH):
        return json_error("Seed not decrypted yet", 500)

    try:
        with open(SEED_PATH, "r", encoding="utf-8") as f:
            seed_hex = f.read().strip()
    except Exception:
        return json_error("Failed to read seed", 500)

    code = str(payload["code"])
    try:
        is_valid = verify_totp_code(seed_hex, code, valid_window=1)
    except Exception:
        return json_error("Verification error", 500)

    return {"valid": bool(is_valid)}
