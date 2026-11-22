"""
Identity Provider Rehearsal & Verification Suite for Secure SMTP.
Tests both Clerk (online/cloud) and Keycloak (offline/airgapped) authentication,
JWKS cryptographic key retrieval, RS256 token verification, claims validation,
and RBAC role enforcement (admin vs analyst).
"""

from __future__ import annotations

import json
import sys
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from secure_smtp.api.auth import verify_offline, verify_token


class MockOidcServer:
    """Lightweight in-memory OIDC/JWKS server for cryptographic rehearsal."""

    def __init__(self):
        # Generate an RSA 2048 keypair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        self.kid = "test-key-id-1"

        # Export public key as JWK
        public_numbers = self.public_key.public_numbers()
        import base64

        def int_to_b64(val: int) -> str:
            raw = val.to_bytes((val.bit_length() + 7) // 8, "big")
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

        self.jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self.kid,
                    "n": int_to_b64(public_numbers.n),
                    "e": int_to_b64(public_numbers.e),
                }
            ]
        }

        self.port = 0
        self.server: HTTPServer | None = None
        self.thread: threading.Thread | None = None

    def start(self):
        jwks_payload = json.dumps(self.jwks).encode("utf-8")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path.endswith("/.well-known/jwks.json") or self.path.endswith("/protocol/openid-connect/certs"):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(jwks_payload)))
                    self.end_headers()
                    self.wfile.write(jwks_payload)
                elif self.path.endswith("/.well-known/openid-configuration"):
                    config = {
                        "issuer": f"http://127.0.0.1:{self.server.server_port}",
                        "jwks_uri": f"http://127.0.0.1:{self.server.server_port}/.well-known/jwks.json",
                        "response_types_supported": ["code", "token", "id_token"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                    }
                    data = json.dumps(config).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                pass  # Quiet logs during test

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def issue_token(self, claims: dict, headers: dict | None = None) -> str:
        h = {"kid": self.kid, **(headers or {})}
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return jwt.encode(claims, pem, algorithm="RS256", headers=h)


def rehearse_keycloak(server: MockOidcServer):
    """Verify Keycloak offline authentication provider with valid and adversarial tokens."""
    print("\n[+] Rehearsing Keycloak (Offline Identity Mode)...")
    issuer = "https://mail-sec.internal/id/realms/pilot"
    jwks_url = f"http://127.0.0.1:{server.port}/protocol/openid-connect/certs"

    settings = SimpleNamespace(
        auth_provider="keycloak",
        offline_issuer=issuer,
        offline_jwks_url=jwks_url,
        pilot_org_id="local-pilot",
    )

    now = datetime.now(UTC)

    # 1. Valid Admin Token
    admin_claims = {
        "iss": issuer,
        "sub": "user_admin_01",
        "aud": "secure-smtp-api",
        "azp": "secure-smtp",
        "typ": "Bearer",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "resource_access": {
            "secure-smtp": {
                "roles": ["admin"]
            }
        }
    }
    admin_token = server.issue_token(admin_claims)
    principal = verify_offline(admin_token, settings)
    assert principal.user_id == "user_admin_01"
    assert principal.org_id == "local-pilot"
    assert principal.role == "admin"
    print("  [✓] Valid Keycloak Admin token verified successfully (role=admin)")

    # 2. Valid Analyst Token
    analyst_claims = {
        "iss": issuer,
        "sub": "user_analyst_01",
        "aud": "secure-smtp-api",
        "azp": "secure-smtp",
        "typ": "Bearer",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "resource_access": {
            "secure-smtp": {
                "roles": ["analyst"]
            }
        }
    }
    analyst_token = server.issue_token(analyst_claims)
    principal_analyst = verify_offline(analyst_token, settings)
    assert principal_analyst.role == "member"
    print("  [✓] Valid Keycloak Analyst token verified successfully (role=member)")

    # 3. Missing Required Roles
    no_role_claims = dict(admin_claims, resource_access={"secure-smtp": {"roles": ["viewer"]}})
    try:
        verify_offline(server.issue_token(no_role_claims), settings)
        raise AssertionError("Should reject user without admin/analyst roles")
    except Exception as e:
        assert getattr(e, "status_code", None) == 403
        print("  [✓] Keycloak token with insufficient role rejected (HTTP 403)")

    # 4. Expired Token
    expired_claims = dict(admin_claims, exp=int((now - timedelta(seconds=10)).timestamp()))
    try:
        verify_offline(server.issue_token(expired_claims), settings)
        raise AssertionError("Should reject expired token")
    except Exception as e:
        assert getattr(e, "status_code", None) == 401
        print("  [✓] Keycloak expired token rejected (HTTP 401)")

    # 5. Invalid Client (azp mismatch)
    bad_azp_claims = dict(admin_claims, azp="rogue-client")
    try:
        verify_offline(server.issue_token(bad_azp_claims), settings)
        raise AssertionError("Should reject bad azp")
    except Exception as e:
        assert getattr(e, "status_code", None) == 403
        print("  [✓] Keycloak token with rogue client azp rejected (HTTP 403)")


def rehearse_clerk(server: MockOidcServer):
    """Verify Clerk cloud authentication provider with valid and adversarial tokens."""
    print("\n[+] Rehearsing Clerk (Cloud / Connected Identity Mode)...")
    issuer = "https://clerk.example.com"
    jwks_url = f"http://127.0.0.1:{server.port}/.well-known/jwks.json"

    settings = SimpleNamespace(
        auth_provider="clerk",
        clerk_issuer=issuer,
        clerk_audience=None,
        clerk_authorized_parties=["https://mail-sec.example.com"],
        pilot_org_id="org_pilot_cloud",
    )

    now = datetime.now(UTC)

    # 1. Valid Clerk Admin Session Token
    clerk_claims = {
        "iss": issuer,
        "sub": "user_clerk_99",
        "sid": "sess_clerk_123",
        "azp": "https://mail-sec.example.com",
        "org_id": "org_pilot_cloud",
        "org_role": "admin",
        "sts": "active",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }

    # Patch PyJWKClient in auth module to use our local mock JWKS server
    with patch("secure_smtp.api.auth.jwks_client") as mock_jwks:
        mock_jwks.return_value = jwt.PyJWKClient(jwks_url)
        with patch("secure_smtp.api.auth.get_settings", return_value=settings):
            token = server.issue_token(clerk_claims)
            principal = verify_token(token)
            assert principal.user_id == "user_clerk_99"
            assert principal.org_id == "org_pilot_cloud"
            assert principal.role == "admin"
            print("  [✓] Valid Clerk Admin token verified successfully (role=admin)")

            # 2. Valid Clerk Member Session Token
            member_claims = dict(clerk_claims, org_role="org:member", sub="user_clerk_member")
            token_member = server.issue_token(member_claims)
            principal_member = verify_token(token_member)
            assert principal_member.role == "member"
            print("  [✓] Valid Clerk Member token verified successfully (role=member)")

            # 3. Wrong Organization ID
            wrong_org = dict(clerk_claims, org_id="org_other_tenant")
            try:
                verify_token(server.issue_token(wrong_org))
                raise AssertionError("Should reject foreign organization")
            except Exception as e:
                assert getattr(e, "status_code", None) == 403
                print("  [✓] Clerk token with foreign organization ID rejected (HTTP 403)")

            # 4. Untrusted Authorized Party (azp)
            untrusted_azp = dict(clerk_claims, azp="https://attacker.com")
            try:
                verify_token(server.issue_token(untrusted_azp))
                raise AssertionError("Should reject untrusted azp")
            except Exception as e:
                assert getattr(e, "status_code", None) == 403
                print("  [✓] Clerk token with untrusted azp rejected (HTTP 403)")

            # 5. Pending Status
            pending_claims = dict(clerk_claims, sts="pending")
            try:
                verify_token(server.issue_token(pending_claims))
                raise AssertionError("Should reject pending session")
            except Exception as e:
                assert getattr(e, "status_code", None) == 403
                print("  [✓] Clerk token with pending status rejected (HTTP 403)")


def main():
    print("=" * 70)
    print(" Secure SMTP — Identity Provider (Clerk & Keycloak) Rehearsal")
    print("=" * 70)
    server = MockOidcServer()
    server.start()
    try:
        rehearse_keycloak(server)
        rehearse_clerk(server)
        print("\n" + "=" * 70)
        print(" [ALL PASSED] Both Clerk and Keycloak identity flows mathematically verified!")
        print("=" * 70)
    finally:
        server.stop()


if __name__ == "__main__":
    main()
