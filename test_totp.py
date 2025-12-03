# test_totp.py
from totp_utils import generate_totp_code, verify_totp_code

# read your decrypted hex seed (created earlier at data/seed.txt)
with open("data/seed.txt", "r", encoding="utf-8") as f:
    hex_seed = f.read().strip()

print("Seed length:", len(hex_seed))
print("Seed preview:", hex_seed[:8] + "..." + hex_seed[-8:])

code = generate_totp_code(hex_seed)
print("Generated TOTP:", code)

# verify immediately
ok = verify_totp_code(hex_seed, code, valid_window=1)
print("Verify (valid_window=1):", ok)