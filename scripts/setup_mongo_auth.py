#!/usr/bin/env python3
"""
Secure SMTP — MongoDB Authentication Setup & Provisioning Utility.

Provisions an enterprise application user with granular roles, verifies
SCRAM-SHA-256 authentication, and generates environment variable configurations.

Usage:
    python scripts/setup_mongo_auth.py
    python scripts/setup_mongo_auth.py --user secure_admin --password my_password
    python scripts/setup_mongo_auth.py --verify
"""

import argparse
import os
import sys
import urllib.parse
from pathlib import Path

# Add src to pythonpath
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from pymongo import MongoClient
from pymongo.errors import OperationFailure

DEFAULT_USER = "secure_admin"
DEFAULT_PASS = ""
DEFAULT_DB = "secure_smtp"
DEFAULT_AUTH_DB = "admin"
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 27017


def parse_args():
    parser = argparse.ArgumentParser(
        description="Provision and verify MongoDB authentication for Secure SMTP."
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("SECURE_SMTP_MONGO_HOST", DEFAULT_HOST),
        help=f"MongoDB host (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SECURE_SMTP_MONGO_PORT", DEFAULT_PORT)),
        help=f"MongoDB port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--user",
        default=os.environ.get("SECURE_SMTP_MONGO_USER", DEFAULT_USER),
        help=f"Application username (default: {DEFAULT_USER})",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("SECURE_SMTP_MONGO_PASSWORD", DEFAULT_PASS),
        help="Application password",
    )
    parser.add_argument(
        "--database",
        default=os.environ.get("SECURE_SMTP_MONGO_DB", DEFAULT_DB),
        help=f"Application database (default: {DEFAULT_DB})",
    )
    parser.add_argument(
        "--auth-db",
        default=os.environ.get("SECURE_SMTP_MONGO_AUTH_DB", DEFAULT_AUTH_DB),
        help=f"Authentication database (default: {DEFAULT_AUTH_DB})",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify connection with current credentials without modifying users",
    )
    args = parser.parse_args()
    if not args.password:
        parser.error("Set SECURE_SMTP_MONGO_PASSWORD; a unique password is required")
    return args


def verify_credentials(host, port, user, password, database, auth_db):
    """Test connecting with credentials."""
    encoded_user = urllib.parse.quote_plus(user)
    encoded_pwd = urllib.parse.quote_plus(password)
    uri = f"mongodb://{encoded_user}:{encoded_pwd}@{host}:{port}/{database}?authSource={auth_db}&authMechanism=SCRAM-SHA-256"
    masked_uri = f"mongodb://{user}:******@{host}:{port}/{database}?authSource={auth_db}"

    print(f"Connecting to: {masked_uri} ...")
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=4000, connectTimeoutMS=4000)
        ping = client.admin.command("ping")
        if ping.get("ok") == 1.0:
            print(f"✅ Authentication SUCCESSFUL as '{user}' on '{auth_db}'!")
            db = client[database]
            print(f"   Database '{database}' accessible (collections: {db.list_collection_names()[:5]})")
            return True
        else:
            print("⚠️ Ping returned non-OK response:", ping)
            return False
    except OperationFailure as e:
        print(f"❌ Authentication FAILED: {e}")
        return False
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return False


def main():
    args = parse_args()
    print("=" * 65)
    print("🛡️ Secure SMTP — MongoDB Authentication Manager")
    print("=" * 65)

    if args.verify:
        success = verify_credentials(
            args.host, args.port, args.user, args.password, args.database, args.auth_db
        )
        sys.exit(0 if success else 1)

    # 1. Connect to MongoDB initially to provision user
    print(f"1. Connecting to MongoDB at {args.host}:{args.port}...")
    try:
        admin_client = MongoClient(
            f"mongodb://{args.host}:{args.port}",
            serverSelectionTimeoutMS=4000,
        )
        admin_client.admin.command("ping")
    except Exception as e:
        print(f"❌ Could not connect to MongoDB at {args.host}:{args.port}: {e}")
        print("   Make sure MongoDB is running before executing this script.")
        sys.exit(1)

    # 2. Check/create user on auth_db
    auth_database = admin_client[args.auth_db]
    print(f"2. Provisioning application user '{args.user}' on database '{args.auth_db}'...")

    try:
        # Check if user exists
        user_info = auth_database.command("usersInfo", args.user)
        user_exists = bool(user_info.get("users"))

        roles = [
            {"role": "readWrite", "db": args.database},
            {"role": "dbAdmin", "db": args.database},
            {"role": "read", "db": args.auth_db},
        ]

        if user_exists:
            print(f"   User '{args.user}' already exists. Updating password & permissions...")
            auth_database.command(
                "updateUser",
                args.user,
                pwd=args.password,
                roles=roles,
            )
            print(f"✅ User '{args.user}' updated.")
        else:
            auth_database.command(
                "createUser",
                args.user,
                pwd=args.password,
                roles=roles,
            )
            print(f"✅ User '{args.user}' successfully created.")

    except OperationFailure as e:
        if "requires authentication" in str(e).lower():
            print("ℹ️ MongoDB already has authentication enabled.")
            print("   Attempting to verify existing credentials...")
        else:
            print(f"⚠️ Operation failure during user provisioning: {e}")

    # 3. Verify authenticated connection
    print("\n3. Testing authenticated connection...")
    success = verify_credentials(
        args.host, args.port, args.user, args.password, args.database, args.auth_db
    )

    # 4. Display environment configuration
    print("\n" + "=" * 65)
    print("📋 Recommended Environment Variables for Secure SMTP:")
    print("=" * 65)
    print(f"export SECURE_SMTP_MONGO_USER=\"{args.user}\"")
    print("Set SECURE_SMTP_MONGO_PASSWORD through your secret manager; password is not printed.")
    print(f"export SECURE_SMTP_MONGO_AUTH_DB=\"{args.auth_db}\"")
    print("export SECURE_SMTP_MONGO_AUTH_MECHANISM=\"SCRAM-SHA-256\"")
    print("export SECURE_SMTP_MONGO_AUTH_REQUIRED=\"true\"")
    print("=" * 65)
    print("Add these to your environment or startup scripts to enforce DB auth.\n")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
