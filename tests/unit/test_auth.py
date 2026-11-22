"""Offline adversarial tests for verified pilot identities (no real identity service)."""
from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

from secure_smtp.api import auth


@pytest.fixture(scope="module")
def signing_keys():
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )


@pytest.fixture
def identity(monkeypatch, signing_keys):
    settings = SimpleNamespace(
        clerk_issuer="https://identity.example.test",
        clerk_audience="secure-smtp-pilot",
        clerk_authorized_parties=["https://pilot.example.test"],
        pilot_org_id="org_pilot",
        enable_live_lab=False,
    )
    monkeypatch.setattr(auth, "get_settings", lambda: settings)
    calls = []

    class OfflineJwks:
        def get_signing_key_from_jwt(self, token):
            calls.append(token)
            return SimpleNamespace(key=signing_keys[0].public_key())

    monkeypatch.setattr(auth, "jwks_client", lambda issuer: OfflineJwks())
    now = int(time.time())
    claims = {
        "iss": settings.clerk_issuer,
        "aud": settings.clerk_audience,
        "azp": settings.clerk_authorized_parties[0],
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + 60,
        "sub": "user_analyst",
        "sid": "sess_verified",
        "org_id": settings.pilot_org_id,
        "org_role": "org:member",
    }

    def sign(payload=None, key=None):
        return jwt.encode(claims if payload is None else payload, key or signing_keys[0], algorithm="RS256", headers={"kid": "offline-test-key"})

    return SimpleNamespace(settings=settings, claims=claims, sign=sign, calls=calls)


@pytest.fixture
def client():
    # Exercise real dependency routing while avoiding unrelated database services.
    app = FastAPI()

    @app.get("/protected")
    async def protected(principal=Depends(auth.verify_api_key)):
        return {"user_id": principal.user_id, "org_id": principal.org_id, "role": principal.role}

    @app.post("/admin")
    async def admin(principal=Depends(auth.require_admin)):
        return {"org_id": principal.org_id}

    @app.post("/lab")
    async def lab(principal=Depends(auth.require_lab_admin)):
        return {"org_id": principal.org_id}

    return TestClient(app)


def assert_rejected(token, status):
    with pytest.raises(HTTPException) as rejected:
        auth.verify_token(token)
    assert rejected.value.status_code == status


def test_valid_v1_session_gets_verified_identity(identity, client):
    response = client.get("/protected", headers={"Authorization": f"Bearer {identity.sign()}"})
    assert response.status_code == 200
    assert response.json() == {"user_id": "user_analyst", "org_id": "org_pilot", "role": "member"}


@pytest.mark.parametrize("role", ["admin", "member", "analyst"])
def test_v2_organization_claims(identity, role):
    claims = {**identity.claims, "v": 2, "o": {"id": "org_pilot", "rol": role}}
    # Legacy fields must not override the active v2 organization or role.
    claims.update(org_id="org_other", org_role="org:admin")
    result = auth.verify_token(identity.sign(claims))
    assert result.org_id == "org_pilot"
    assert result.role == role


@pytest.mark.parametrize("claim,value,status", [
    ("exp", 1, 401),
    ("nbf", 4102444800, 401),
    ("iat", 4102444800, 401),
    ("iss", "https://attacker.example.test", 401),
    ("aud", "another-application", 401),
    ("azp", "https://evil.example.test", 403),
    ("azp", "https://pilot.example.test.evil.test", 403),
    ("org_id", "org_other", 403),
    ("org_id", "", 403),
    ("sub", "", 403),
    ("sid", "", 403),
    ("sts", "pending", 403),
])
def test_signed_but_invalid_claims_are_rejected(identity, claim, value, status):
    assert_rejected(identity.sign({**identity.claims, claim: value}), status)


@pytest.mark.parametrize("claim", ["exp", "nbf", "iat", "iss", "sub", "sid", "azp", "aud"])
def test_required_claims_cannot_be_omitted(identity, claim):
    claims = identity.claims.copy()
    del claims[claim]
    assert_rejected(identity.sign(claims), 401)


@pytest.mark.parametrize("organization", [None, {}, "org_pilot", {"id": "org_other", "rol": "admin"}])
def test_v2_requires_valid_active_organization(identity, organization):
    claims = {**identity.claims, "v": 2, "o": organization}
    assert_rejected(identity.sign(claims), 403)


def test_wrong_signature_is_rejected(identity, signing_keys):
    assert_rejected(identity.sign(key=signing_keys[1]), 401)


def test_hmac_algorithm_cannot_replace_rsa(identity):
    token = jwt.encode(identity.claims, "not-a-server-secret" * 3, algorithm="HS256")
    assert_rejected(token, 401)


def test_unsigned_token_is_rejected(identity):
    assert_rejected(jwt.encode(identity.claims, key="", algorithm="none"), 401)


@pytest.mark.parametrize("token", ["", "malformed", "securesmtp_live_secret_key", "x" * 16385])
def test_malformed_old_and_oversized_credentials_are_rejected(identity, token):
    assert_rejected(token, 401)


@pytest.mark.parametrize("kind", ["header", "query", "missing"])
def test_browser_shared_key_paths_are_not_authentication(identity, client, kind):
    response = client.get("/protected", headers={"X-API-Key": "securesmtp_live_secret_key"} if kind == "header" else {},
                          params={"api_key": "securesmtp_live_secret_key"} if kind == "query" else {})
    assert response.status_code == 401
    assert identity.calls == []


def test_non_bearer_authorization_is_rejected(identity, client):
    assert client.get("/protected", headers={"Authorization": f"Basic {identity.sign()}"}).status_code == 401


def test_member_cannot_use_admin_or_lab_controls(identity, client):
    headers = {"Authorization": f"Bearer {identity.sign()}"}
    assert client.post("/admin", headers=headers).status_code == 403
    assert client.post("/lab", headers=headers).status_code == 403


def test_admin_does_not_override_disabled_lab(identity, client):
    token = identity.sign({**identity.claims, "org_role": "org:admin"})
    headers = {"Authorization": f"Bearer {token}"}
    assert client.post("/admin", headers=headers).status_code == 200
    assert client.post("/lab", headers=headers).status_code == 403
    identity.settings.enable_live_lab = True
    assert client.post("/lab", headers=headers).status_code == 200


def test_scope_cannot_be_overridden_by_request_query():
    principal = auth.Principal("u", "org_pilot", "member", 123)
    original = {"org_id": "org_other", "id": 5}
    assert auth.scope(principal, original) == {"org_id": "org_pilot", "id": 5}
    assert original == {"org_id": "org_other", "id": 5}


@pytest.mark.parametrize("field,value", [
    ("clerk_issuer", "http://identity.example.test"),
    ("clerk_issuer", ""),
    ("pilot_org_id", ""),
    ("clerk_authorized_parties", []),
])
def test_missing_configuration_fails_closed_before_key_lookup(identity, field, value):
    setattr(identity.settings, field, value)
    assert_rejected(identity.sign(), 503)
    assert identity.calls == []


def test_jwks_connection_failure_never_grants_access(identity, monkeypatch):
    class UnavailableJwks:
        def get_signing_key_from_jwt(self, token):
            raise jwt.PyJWKClientConnectionError("unreachable")
    monkeypatch.setattr(auth, "jwks_client", lambda issuer: UnavailableJwks())
    assert_rejected(identity.sign(), 503)


def test_unknown_signing_key_never_grants_access(identity, monkeypatch):
    class UnknownJwks:
        def get_signing_key_from_jwt(self, token):
            raise jwt.PyJWKClientError("unknown kid")
    monkeypatch.setattr(auth, "jwks_client", lambda issuer: UnknownJwks())
    assert_rejected(identity.sign(), 401)


@pytest.mark.parametrize("role,expected", [("admin", "admin"), ("analyst", "member"), ("unassigned", None)])
def test_keycloak_client_role_and_issuer(identity, monkeypatch, signing_keys, role, expected):
    settings = identity.settings
    settings.auth_provider = "keycloak"
    settings.offline_issuer = "https://pilot.invalid/id/realms/pilot"
    settings.offline_jwks_url = "http://identity:8080/id/realms/pilot/protocol/openid-connect/certs"
    monkeypatch.setattr(auth, "offline_keys", lambda url: auth.jwks_client("fixture"))
    claims = dict(identity.claims, typ="Bearer", iss=settings.offline_issuer, aud="secure-smtp-api",
                  azp="secure-smtp", resource_access={"secure-smtp": {"roles": [role]}})
    if expected:
        principal = auth.verify_token(identity.sign(claims))
        assert (principal.role, principal.org_id) == (expected, settings.pilot_org_id)
    else:
        with pytest.raises(HTTPException) as denied:
            auth.verify_token(identity.sign(claims))
        assert denied.value.status_code == 403
    for changed in (dict(iss=settings.clerk_issuer), dict(aud="elsewhere"), dict(azp="account"), dict(typ="ID")):
        with pytest.raises(HTTPException):
            auth.verify_token(identity.sign({**claims, **changed}))
    with pytest.raises(HTTPException):
        auth.verify_token(identity.sign(claims, signing_keys[1]))


@pytest.mark.parametrize("resources", [None, [], {"secure-smtp":None}, {"secure-smtp":{"roles":[{}]}}, {"secure-smtp":{"roles":"admin"}}])
def test_keycloak_malformed_roles_fail_closed(identity, monkeypatch, resources):
    settings = identity.settings
    settings.auth_provider = "keycloak"
    settings.offline_issuer = "https://pilot.invalid/id/realms/pilot"
    settings.offline_jwks_url = "http://identity/certs"
    monkeypatch.setattr(auth, "offline_keys", lambda url: auth.jwks_client("fixture"))
    claims = dict(identity.claims, typ="Bearer", iss=settings.offline_issuer, aud="secure-smtp-api",
                  azp="secure-smtp", resource_access=resources)
    with pytest.raises(HTTPException) as denied:
        auth.verify_token(identity.sign(claims))
    assert denied.value.status_code == 403


def test_local_issuer_does_not_bypass_signature_verification(identity, monkeypatch):
    identity.settings.clerk_issuer = 'https://clerk.local'
    class RejectUnsigned:
        def get_signing_key_from_jwt(self, token):
            raise jwt.PyJWTError('Not a signed session')
    monkeypatch.setattr(auth, 'jwks_client', lambda issuer: RejectUnsigned())
    for token in ['local-admin-session', 'local-member-session', 'anything']:
        assert_rejected(token, 401)


@pytest.mark.parametrize('version', [1, 2])
def test_public_registration_uses_private_member_workspace(identity, version):
    identity.settings.public_registration = True
    identity.settings.pilot_org_id = ''
    claims = {k: v for k, v in identity.claims.items() if k not in ('org_id', 'org_role')}
    claims['v'] = version
    first = auth.verify_token(identity.sign(claims))
    second = auth.verify_token(identity.sign({**claims, 'sub': 'user_other', 'org_role': 'org:admin'}))
    assert first.org_id == 'personal:user_analyst'
    assert second.org_id == 'personal:user_other'
    assert first.role == second.role == 'member'
    assert auth.scope(first) != auth.scope(second)


def test_public_signup_does_not_grant_pilot_or_admin_access(identity, client):
    identity.settings.public_registration = True
    claims = {k: v for k, v in identity.claims.items() if k not in ('org_id', 'org_role')}
    headers = {'Authorization': 'Bearer ' + identity.sign(claims)}
    assert client.get('/protected', headers=headers).json()['org_id'] != 'org_pilot'
    assert client.post('/admin', headers=headers).status_code == 403
    assert client.post('/lab', headers=headers).status_code == 403
    with pytest.raises(HTTPException):
        auth.verify_token(identity.sign({**claims, 'org_id': 'org_other'}))
    with pytest.raises(HTTPException):
        auth.verify_token(identity.sign({**claims, 'sts': 'pending'}))
