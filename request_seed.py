import requests

API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws/"
STUDENT_ID = "23P31A0502"
GITHUB_REPO_URL = "https://github.com/SaiDurga-28/Secure-Crypto-Service_23P31A0502"

# 1. Read student public key from PEM file
with open("student_public.pem", "r") as f:
    public_key = f.read()

# 2. Prepare JSON payload exactly as instructor expects
payload = {
    "student_id": STUDENT_ID,
    "github_repo_url": GITHUB_REPO_URL,
    "public_key": public_key
}

# 3. Send POST request
response = requests.post(API_URL, json=payload)
response.raise_for_status()

# 4. Parse JSON response
data = response.json()

encrypted_seed = data["encrypted_seed"]

# 5. Save seed to file
with open("encrypted_seed.txt", "w") as f:
    f.write(encrypted_seed)

print("Encrypted seed saved to encrypted_seed.txt")