#!/usr/bin/env python3
"""
Secure SMTP — 1-Click Database Recovery & Restore Utility
Restores a compressed MongoDB Atlas snapshot archive into the database.
"""

import os
import subprocess
import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))

try:
    from secure_smtp.config import get_settings
    settings = get_settings()
    mongo_uri = settings.mongo_uri
    db_name = settings.mongo_db
except Exception:
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

# Determine target archive
if len(sys.argv) > 1:
    archive_path = Path(sys.argv[1]).resolve()
else:
    # Pick the most recent backup in backups/
    if not backups_dir.exists():
        print(f"[-] Error: No backups directory found at {backups_dir}")
        sys.exit(1)
    archives = sorted(backups_dir.glob("*.archive.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not archives:
        print(f"[-] Error: No .archive.gz files found in {backups_dir}")
        sys.exit(1)
    archive_path = archives[0]

if not archive_path.exists():
    print(f"[-] Error: Target backup archive does not exist: {archive_path}")
    sys.exit(1)

print(f"[*] Starting MongoDB Atlas recovery from archive...")
print(f"[*] Source archive: {archive_path}")
print(f"[*] Target database: {db_name}")

cmd = [
    "mongorestore",
    f"--uri={mongo_uri}",
    f"--archive={str(archive_path)}",
    "--gzip",
    "--drop",
]

try:
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    print(f"[+] Recovery completed successfully!")
    print(f"[+] Restored all collections into database '{db_name}' with --drop option.")
except subprocess.CalledProcessError as e:
    print(f"[-] Restore failed with return code {e.returncode}:")
    print(e.stderr or e.stdout)
    sys.exit(1)
except FileNotFoundError:
    print("[-] Error: 'mongorestore' command not found. Ensure MongoDB Database Tools are installed.")
    sys.exit(1)
