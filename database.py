import json
from pathlib import Path
from utils import hash_password

DB_FILE = Path("users.json")

# Load existing users if file exists
if DB_FILE.exists():
    with open(DB_FILE, "r") as f:
        fake_users_db = json.load(f)
else:
    fake_users_db = {}

# Ensure default superadmin always exists
if "superadmin" not in fake_users_db:
    fake_users_db["superadmin"] = {
        "username": "superadmin",
        "password": hash_password("supersecure123"),
        "role": "superadmin"
    }

# Save users to disk
def save_users():
    with open(DB_FILE, "w") as f:
        json.dump(fake_users_db, f, indent=2)
