"""Provision a single local pilot operator without putting passwords in Git.

Run from the repository root:
    PYTHONPATH=src .venv/bin/python scripts/provision_local_operator.py
This rotates the local operator password. Restart the backend afterwards.
"""

import os
import secrets
from pathlib import Path

from dotenv import dotenv_values, set_key

from secure_smtp.api.sessions_auth import hash_password

if __name__ == "__main__":
    env = Path(".env")
    credential_file = Path("output/private/local-operator.txt")
    credential_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    password = secrets.token_urlsafe(24)
    current = dotenv_values(env)
    email = current.get("SECURE_SMTP_LOCAL_ADMIN_EMAIL") or "operator@securesmtp.local"
    set_key(str(env), "SECURE_SMTP_LOCAL_ADMIN_EMAIL", email)
    set_key(str(env), "SECURE_SMTP_LOCAL_PASSWORD_HASH", hash_password(password))
    set_key(str(env), "SECURE_SMTP_CLERK_ISSUER", "")
    if (
        not current.get("SECURE_SMTP_API_KEY")
        or current.get("SECURE_SMTP_API_KEY") == "securesmtp_live_secret_key"
    ):
        set_key(str(env), "SECURE_SMTP_API_KEY", secrets.token_urlsafe(32))
    os.chmod(env, 0o600)
    frontend_env = Path("frontend/.env.local")
    set_key(str(frontend_env), "VITE_CLERK_PUBLISHABLE_KEY", "")
    set_key(str(frontend_env), "VITE_API_BASE", "")
    set_key(str(frontend_env), "VITE_API_URL", "")
    os.chmod(frontend_env, 0o600)
    fd = os.open(credential_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(
            f"Local pilot account\nEmail: {email}\nPassword: {password}\n\nKeep private. Restart the backend and frontend after provisioning.\nOnly the salted hash is stored in .env. Delete this file after saving the password securely.\n"
        )
    print(f"Provisioned {email}. Private credentials: {credential_file.resolve()}")
