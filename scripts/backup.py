#!/usr/bin/env python3
"""
Secure SMTP — 1-Click Database Backup Utility
Dumps MongoDB Atlas collections to a timestamped compressed archive in backups/
"""

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Ensure src is on python path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))

try:
    from secure_smtp.config import get_settings
    settings = get_settings()
    mongo_uri = settings.mongo_uri
    db_name = settings.mongo_db
except Exception as e:
    # Fallback to direct .env read
    from pydantic_settings import BaseSettings
    env_file = root_dir / ".env"
    mongo_uri = ""
    db_name = "secure_smtp"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("SECURE_SMTP_MONGO_URI="):
                mongo_uri = line.split("=", 1)[1].strip("'\"")
            elif line.startswith("SECURE_SMTP_MONGO_DB="):
                db_name = line.split("=", 1)[1].strip("'\"")

if not mongo_uri:
    print("[-] Error: SECURE_SMTP_MONGO_URI is not configured in .env")
    sys.exit(1)

backups_dir = root_dir / "backups"
backups_dir.mkdir(parents=True, exist_ok=True)

timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
archive_name = f"secure_smtp_{db_name}_{timestamp}.archive.gz"
archive_path = backups_dir / archive_name

print(f"[*] Starting MongoDB Atlas backup for database '{db_name}'...")
print(f"[*] Destination: {archive_path}")

cmd = [
    "mongodump",
    f"--uri={mongo_uri}",
    f"--db={db_name}",
    f"--archive={str(archive_path)}",
    "--gzip",
]

try:
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    size_mb = archive_path.stat().st_size / (1024 * 1024)
    print(f"[+] Backup completed successfully!")
    print(f"[+] Archive file: {archive_path.name} ({size_mb:.2f} MB)")
    print(f"[+] Full path:    {archive_path}")
except subprocess.CalledProcessError as e:
    print(f"[-] Backup failed with return code {e.returncode}:")
    print(e.stderr or e.stdout)
    sys.exit(1)
except FileNotFoundError:
    print("[-] Error: 'mongodump' command not found. Ensure MongoDB Database Tools are installed.")
    sys.exit(1)
