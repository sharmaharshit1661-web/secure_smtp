#!/usr/bin/env python3
"""
Live Identity Provider Connectivity & Claim Validator for Secure SMTP.

Can be run by operators against live Clerk or Keycloak endpoints:
  python scripts/validate_identity_provider.py --provider clerk --issuer https://... --org-id ...
  python scripts/validate_identity_provider.py --provider keycloak --jwks-url http://...
"""

import argparse
import json
import sys
import urllib.request
from urllib.error import URLError


def validate_clerk(issuer: str, org_id: str | None = None, pubkey: str | None = None):
    print(f"[*] Validating live Clerk instance at: {issuer}")
    jwks_url = issuer.rstrip("/") + "/.well-known/jwks.json"

    try:
        req = urllib.request.Request(jwks_url, headers={"User-Agent": "SecureSMTP-Validator/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            keys = data.get("keys", [])
            print(f"[✓] Successfully retrieved Clerk JWKS. Found {len(keys)} active cryptographic key(s).")
            for k in keys:
                print(f"    - Key ID (kid): {k.get('kid')}, Alg: {k.get('alg', 'RS256')}, Type: {k.get('kty')}")
    except URLError as e:
        print(f"[✗] Failed to connect to Clerk JWKS: {e}")
        return False

    if pubkey:
        if pubkey.startswith("pk_test_") or pubkey.startswith("pk_live_"):
            print(f"[✓] Publishable key format valid ({pubkey[:12]}...)")
        else:
            print("[!] Warning: Publishable key does not have standard prefix.")

    if org_id:
        print(f"[✓] Pilot organization ID configured: {org_id}")

    return True


def validate_keycloak(jwks_url: str, realm_url: str | None = None):
    print(f"[*] Validating live Keycloak JWKS at: {jwks_url}")
    try:
        req = urllib.request.Request(jwks_url, headers={"User-Agent": "SecureSMTP-Validator/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            keys = data.get("keys", [])
            print(f"[✓] Successfully retrieved Keycloak JWKS. Found {len(keys)} active key(s).")
            for k in keys:
                print(f"    - Key ID (kid): {k.get('kid')}, Alg: {k.get('alg', 'RS256')}, Use: {k.get('use')}")
    except URLError as e:
        print(f"[✗] Failed to connect to Keycloak JWKS: {e}")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="Validate Clerk or Keycloak setup for Secure SMTP")
    parser.add_argument("--provider", choices=["clerk", "keycloak"], default="clerk")
    parser.add_argument("--issuer", help="Clerk HTTPS issuer URL")
    parser.add_argument("--jwks-url", help="Keycloak JWKS URL")
    parser.add_argument("--org-id", help="Clerk organization ID")
    parser.add_argument("--pubkey", help="Clerk publishable key")

    args = parser.parse_args()

    if args.provider == "clerk":
        if not args.issuer:
            print("Error: --issuer required for Clerk validation (e.g. https://your-app.clerk.accounts.dev)")
            sys.exit(1)
        ok = validate_clerk(args.issuer, args.org_id, args.pubkey)
    else:
        if not args.jwks_url:
            print("Error: --jwks-url required for Keycloak validation")
            sys.exit(1)
        ok = validate_keycloak(args.jwks_url)

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
