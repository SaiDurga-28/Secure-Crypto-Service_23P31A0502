#!/usr/bin/env python3
# scripts/log_2fa_cron.py
from datetime import datetime, timezone
from pathlib import Path
import traceback
import os, sys
# ensure project root (/app) is on python path so imports like "import totp_utils" work
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))   # /app/scripts
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)                # /app
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from totp_utils import generate_totp_code  # must be importable (same repo)

SEED_PATH = Path("/data/seed.txt")
OUT_PATH = Path("/cron/last_code.txt")

def utc_now_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def main():
    try:
        if not SEED_PATH.exists():
            print(f"{utc_now_str()} - ERROR: seed not found", flush=True)
            return 1
        hex_seed = SEED_PATH.read_text().strip()
        if len(hex_seed) != 64:
            print(f"{utc_now_str()} - ERROR: invalid seed length: {len(hex_seed)}", flush=True)
            return 1
        code = generate_totp_code(hex_seed)
        line = f"{utc_now_str()} - 2FA Code: {code}\n"
        OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with OUT_PATH.open("a", encoding="utf-8") as f:
            f.write(line)
        return 0
    except Exception:
        OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with OUT_PATH.open("a", encoding="utf-8") as f:
            f.write(f"{utc_now_str()} - EXCEPTION: {traceback.format_exc()}\n")
        return 2

if __name__ == "__main__":
    sys.exit(main())
