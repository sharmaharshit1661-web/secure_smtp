"""Print a salted password hash for SECURE_SMTP_LOCAL_PASSWORD_HASH.

Run: PYTHONPATH=src .venv/bin/python scripts/hash_operator_password.py
The password is entered without echo and never stored in source.
"""

from getpass import getpass

from secure_smtp.api.sessions_auth import hash_password

if __name__ == "__main__":
    password = getpass("Operator password (at least 14 characters): ")
    if len(password) < 14:
        raise SystemExit("Use at least 14 characters")
    if password != getpass("Confirm password: "):
        raise SystemExit("Passwords do not match")
    print(hash_password(password))
