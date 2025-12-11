#!/usr/bin/env python3
"""
decrypt_seed.py

Decrypt encrypted_seed.txt (base64) or encrypted_seed.bin and write persistent
hex seed to /data/seed.txt (required by grader). Performs validation:
 - decrypted value must be a 64-character hex string (lower or upper case).
 - creates /data directory if missing and sets secure permissions.

Usage:
    python3 decrypt_seed.py
"""
import base64
import os
import re
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Input files (in repo during request step)
ENCRYPTED_B64 = Path("encrypted_seed.txt")
ENCRYPTED_BIN = Path("encrypted_seed.bin")

# Output persistent path required by grader
SEED_PATH = Path("/data/seed.txt")

# Private key in repo (committed per assignment)
PRIV_PATH = Path("student_private.pem")

HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")

def load_ciphertext():
    if ENCRYPTED_B64.exists():
        b64 = ENCRYPTED_B64.read_text().strip()
        try:
            return base64.b64decode(b64)
        except Exception as e:
            print(f"ERROR: Failed to base64-decode {ENCRYPTED_B64}: {e}", file=sys.stderr)
            sys.exit(2)
    elif ENCRYPTED_BIN.exists():
        return ENCRYPTED_BIN.read_bytes()
    else:
        print("ERROR: No encrypted_seed.txt (base64) or encrypted_seed.bin found. Run request step first.", file=sys.stderr)
        sys.exit(2)

def load_private_key(path: Path):
    if not path.exists():
        print(f"ERROR: Private key not found at {path}", file=sys.stderr)
        sys.exit(3)
    data = path.read_bytes()
    try:
        return serialization.load_pem_private_key(data, password=None)
    except Exception as e:
        print(f"ERROR: Failed to load private key: {e}", file=sys.stderr)
        sys.exit(3)

def try_decrypt(private_key, ciphertext, mgf_hash, algo_hash):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=mgf_hash),
            algorithm=algo_hash,
            label=None
        )
    )

def validate_hex_seed(s: str) -> bool:
    return bool(HEX_RE.fullmatch(s))

def save_seed(hex_seed: str, out_path: Path = SEED_PATH):
    # Ensure directory exists
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Write seed as text (no extra whitespace)
    out_path.write_text(hex_seed, encoding="utf-8")

    # Set secure permissions: readable/writeable by owner only (600)
    try:
        os.chmod(out_path, 0o600)
    except PermissionError:
        # On some platforms (Windows) chmod may be limited; ignore but warn
        print("WARNING: Could not set file permissions on seed file (chmod 600)", file=sys.stderr)

if __name__ == "__main__":
    ciphertext = load_ciphertext()
    private_key = load_private_key(PRIV_PATH)

    decrypted = None
    for label in ("OAEP-SHA256", "OAEP-SHA1"):
        try:
            if label == "OAEP-SHA256":
                pt = try_decrypt(private_key, ciphertext, hashes.SHA256(), hashes.SHA256())
            else:
                pt = try_decrypt(private_key, ciphertext, hashes.SHA1(), hashes.SHA1())
            # attempt to decode as UTF-8 text
            try:
                decoded = pt.decode("utf-8").strip()
            except Exception:
                decoded = None
            if decoded:
                # Found some textual plaintext — assume this is the hex seed
                decrypted = decoded
                print(f"Decryption successful with {label}.")
                break
            else:
                # raw bytes; try to decode as ascii/hex
                try:
                    decoded = pt.decode("ascii").strip()
                    decrypted = decoded
                    print(f"Decryption successful with {label} (ascii decode).")
                    break
                except Exception:
                    # use hex representation of bytes if it's exactly 32 bytes (i.e., 64 hex chars)
                    if len(pt) == 32:
                        decrypted = pt.hex()
                        print(f"Decryption successful with {label} (binary -> hex).")
                        break
                    else:
                        # continue trying other schemes
                        print(f"{label} produced non-text/plain result; continuing...", file=sys.stderr)
        except Exception as e:
            print(f"{label} failed: {e}", file=sys.stderr)

    if decrypted is None:
        print("ERROR: Decryption failed with both OAEP-SHA256 and OAEP-SHA1. Check encryption scheme.", file=sys.stderr)
        sys.exit(4)

    # Validate decrypted seed: must be 64 hex chars
    if not validate_hex_seed(decrypted):
        print(f"ERROR: Decrypted value is not a 64-character hex string: '{decrypted[:80]}'", file=sys.stderr)
        sys.exit(5)

    # Save to persistent path
    try:
        save_seed(decrypted, SEED_PATH)
        print(f"Saved decrypted seed to {SEED_PATH}")
        # optional: also save a local copy for debugging (not required)
        Path("decrypted_seed.txt").write_text(decrypted, encoding="utf-8")
        sys.exit(0)
    except Exception as e:
        print(f"ERROR: Failed to save seed: {e}", file=sys.stderr)
        sys.exit(6)
