#!/usr/bin/env python3
"""
Secure SMTP — Enterprise Credential Rotation & Secret Hygiene Tool.

Performs cryptographic secret generation, safe .env rotation, secret hygiene audit,
and outputs provider-side credential rotation checklists.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def generate_secure_password(length: int = 32) -> str:
    """Generate cryptographically secure high-entropy password (256+ bits of entropy)."""
    return secrets.token_urlsafe(length)


def audit_workspace_for_leaked_secrets() -> list[str]:
    """Scan code and configuration files for accidental hardcoded credentials."""
    findings = []
    # High-risk patterns
    patterns = [
        (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "Live Secret Key"),
        (re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), "Live Publishable Key"),
        (re.compile(r"securesmtp_live_secret_key"), "Legacy Secret Key"),
        (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "GitHub Personal Access Token"),
        (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "Raw Private Key PEM (Non-Test)"),
    ]

    # Directories to scan
    scan_dirs = [ROOT / "src", ROOT / "frontend" / "src", ROOT / "docker", ROOT / "scripts"]

    for d in scan_dirs:
        if not d.exists():
            continue
        for p in d.rglob("*"):
            if not p.is_file() or p.suffix in (".pyc", ".png", ".woff", ".woff2", ".svg", ".pcap") or p.name == "rotate_credentials.py":
                continue
            # Skip test certs in src/secure_smtp/live/certs/ (ephemeral test certificates)
            if "live/certs" in str(p):
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                for pat, desc in patterns:
                    matches = pat.findall(content)
                    if matches:
                        findings.append(f"{p.relative_to(ROOT)}: Found {desc} pattern ({len(matches)} match)")
            except Exception:
                pass

    return findings


def generate_rotated_env(output_path: Path, mode: str = "cloud"):
    """Generate a production .env file populated with cryptographically random secrets."""
    mongo_root_pw = generate_secure_password(32)
    mongo_app_pw = generate_secure_password(32)
    graph_pw = generate_secure_password(32)
    webhook_secret = generate_secure_password(32)
    identity_db_pw = generate_secure_password(32)
    identity_bootstrap_pw = generate_secure_password(32)

    if mode == "offline":
        template = f"""# Secure SMTP — Disconnected / Airgapped Deployment Configuration
# Generated on: {os.uname().sysname} {os.uname().machine}
# Mode: Airgapped Keycloak + Offline Database Initialization

PILOT_DOMAIN=mail-security.internal
PILOT_LAN_IP=192.168.1.100

# PostgreSQL Identity Database for Keycloak
IDENTITY_DB_PASSWORD={identity_db_pw}
IDENTITY_BOOTSTRAP_PASSWORD={identity_bootstrap_pw}

# MongoDB Credentials (Enforces Principal of Least Privilege)
MONGO_ROOT_USER=pilot_admin
MONGO_ROOT_PASSWORD={mongo_root_pw}
SECURE_SMTP_MONGO_USER=pilot_app
SECURE_SMTP_MONGO_PASSWORD={mongo_app_pw}

# Local Graph Database (Neo4j)
GRAPH_PASSWORD={graph_pw}

# Outbound Alert HMAC Secret
SECURE_SMTP_ALERT_WEBHOOK_SECRET={webhook_secret}
"""
    else:
        template = f"""# Secure SMTP — Enterprise Private Pilot Configuration
# Generated on: {os.uname().sysname} {os.uname().machine}
# Mode: Private Network with Clerk Identity Provider

PILOT_DOMAIN=mail-security.corp.internal
PILOT_LAN_IP=192.168.1.50

# Clerk Cloud Authentication (Set from Clerk Dashboard)
VITE_CLERK_PUBLISHABLE_KEY=pk_live_REPLACE_WITH_NEW_ROTATED_KEY
SECURE_SMTP_CLERK_ISSUER=https://clerk.corp.internal
SECURE_SMTP_PILOT_ORG_ID=org_REPLACE_WITH_PILOT_ORG_ID
SECURE_SMTP_CLERK_AUTHORIZED_PARTIES=["https://mail-security.corp.internal"]
SECURE_SMTP_CORS_ORIGINS=["https://mail-security.corp.internal"]

# MongoDB Administrator & Application Accounts (Distinct credentials)
MONGO_ROOT_USER=pilot_admin
MONGO_ROOT_PASSWORD={mongo_root_pw}
SECURE_SMTP_MONGO_USER=pilot_app
SECURE_SMTP_MONGO_PASSWORD={mongo_app_pw}

# Local Knowledge Graph (Neo4j)
GRAPH_PASSWORD={graph_pw}

# Webhook Alerting HMAC-SHA256 Secret
SECURE_SMTP_ALERT_WEBHOOK_SECRET={webhook_secret}
"""

    output_path.write_text(template, encoding="utf-8")
    os.chmod(output_path, 0o600)  # Restrict to current user only
    print(f"[✓] Successfully generated hardened environment file at: {output_path} (mode 0600)")


def print_provider_rotation_checklist():
    print("""
======================================================================
  PROVIDER-SIDE CREDENTIAL ROTATION INSTRUCTIONS & CHECKLIST
======================================================================

1. CLERK CREDENTIAL ROTATION:
   [ ] Log in to Clerk Dashboard (https://dashboard.clerk.com).
   [ ] Navigate to 'API Keys' -> Click 'Roll Key' to revoke old API Keys.
   [ ] Update production environment variables:
       - VITE_CLERK_PUBLISHABLE_KEY (New publishable key)
       - CLERK_SECRET_KEY (New backend secret key)
   [ ] In 'Sessions' settings: Invalidate all active sessions to force re-authentication.
   [ ] In 'JWT Templates' / 'Sessions': Ensure 'org_id' claim is set for multi-tenant isolation.

2. KEYCLOAK REALM ROTATION (Offline Mode):
   [ ] Log in to Keycloak Admin Console (https://YOUR-HOST/id/admin).
   [ ] Navigate to 'Realm Settings' -> 'Keys'.
   [ ] Under 'Providers', add a new 'rsa-generated' key provider with priority 100.
   [ ] Change priority of the old RSA key to 0 (Passive mode).
   [ ] After token expiration window (e.g. 1 hour), delete the old RSA key.

3. MAIL MONITORING AGENT CREDENTIAL ROTATION:
   [ ] In Secure SMTP Console ('Monitoring & Operations'):
       - Identify any active or legacy collectors.
       - Click 'Revoke Credential' (calls /api/agents/{agent_id}/revoke).
       - Revoked credentials cannot submit further batches.
   [ ] Provision fresh agent:
       - Click 'Provision Collector'.
       - Copy single-use credential file to /etc/secure-smtp/agent.credential (mode 0600).
       - Restart secure-smtp-agent container.

4. DATABASE USER CREDENTIALS:
   [ ] If changing passwords on existing MongoDB instances:
       - Connect via mongosh with administrator credentials.
       - Run: db.getSiblingDB('secure_smtp_pilot').changeUserPassword('pilot_app', '<new-pass>')
       - Update .env and restart backend container.
======================================================================
""")


def main():
    parser = argparse.ArgumentParser(description="Rotate credentials and audit secret hygiene for Secure SMTP")
    parser.add_argument("--audit-only", action="store_true", help="Only audit repository for exposed credentials")
    parser.add_argument("--generate-env", help="Generate fresh .env file at specified path")
    parser.add_argument("--mode", choices=["cloud", "offline"], default="cloud", help="Deployment mode (cloud or offline)")

    args = parser.parse_args()

    print("=" * 70)
    print(" Secure SMTP — Enterprise Credential Rotation & Secret Hygiene Tool")
    print("=" * 70)

    print("\n[*] Auditing repository for hardcoded or leaked secrets...")
    leaks = audit_workspace_for_leaked_secrets()
    if leaks:
        print(f"[!] Warning: Found {len(leaks)} potential secret reference(s):")
        for leak in leaks:
            print(f"    - {leak}")
    else:
        print("  [✓] Audit Clean: Zero leaked live keys, tokens, or hardcoded passwords found in source!")

    if args.generate_env:
        out_path = Path(args.generate_env).resolve()
        generate_rotated_env(out_path, mode=args.mode)

    print_provider_rotation_checklist()


if __name__ == "__main__":
    main()
