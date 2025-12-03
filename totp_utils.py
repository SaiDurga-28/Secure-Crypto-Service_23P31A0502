import base64
import pyotp

def hex_to_base32(hex_seed: str) -> str:
    """Convert 64-char hex seed -> BASE32 string (no '=' padding)."""
    if len(hex_seed) != 64:
        raise ValueError("hex_seed must be 64 hex chars")
    seed_bytes = bytes.fromhex(hex_seed)
    b32 = base64.b32encode(seed_bytes).decode("utf-8").rstrip("=")
    return b32

def generate_totp_code(hex_seed: str) -> str:
    """Return current 6-digit TOTP code as string."""
    b32 = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30)  # SHA1 default
    return totp.now()

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a TOTP code.
    valid_window: number of 30s periods to allow before/after (default 1 -> ±30s).
    """
    b32 = hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30)
    return totp.verify(code, valid_window=valid_window)