"""Verified Clerk session identity. No browser API keys or anonymous fallback."""

import hashlib
import secrets
import time
from dataclasses import dataclass
from functools import lru_cache

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.concurrency import run_in_threadpool

from secure_smtp.config import get_settings

AUTH_REQUIRED = True
http_bearer = HTTPBearer(auto_error=False)


@lru_cache(maxsize=1)
def get_jwt_secret() -> str:
    settings = get_settings()
    raw = (
        getattr(settings, "api_key", "")
        or getattr(settings, "mongo_password", "")
        or "secure-smtp-enterprise-token-signing-secret-2026-auth"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"{salt}:{key.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        if stored_hash.startswith("pbkdf2_sha256$"):
            parts = stored_hash.split("$")
            if len(parts) == 4:
                _, iters_str, salt, key_hex = parts
                expected = hashlib.pbkdf2_hmac(
                    "sha256", password.encode("utf-8"), salt.encode("utf-8"), int(iters_str)
                )
                return secrets.compare_digest(expected.hex(), key_hex)
        salt, key_hex = stored_hash.split(":", 1)
        expected = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
        )
        return secrets.compare_digest(expected.hex(), key_hex)
    except Exception:
        return False


def create_access_token(user_id: str, email: str, role: str, org_id: str | None = None) -> str:
    now = int(time.time())
    payload = {
        "iss": "secure-smtp-native",
        "sub": user_id,
        "email": email,
        "role": role,
        "org_id": org_id or get_settings().pilot_org_id or f"org_{user_id}",
        "iat": now,
        "exp": now + 86400 * 7,  # 7 days
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm="HS256")


@dataclass(frozen=True)
class Principal:
    user_id: str
    org_id: str
    role: str
    expires_at: int


def scope(principal: Principal, query: dict | None = None) -> dict:
    # Callers cannot override the verified organization.
    return {**(query or {}), "org_id": principal.org_id}


def visible_scope(principal: Principal, query: dict | None = None) -> dict:
    """Exclude staged evidence from failed or still-running assessments."""
    return scope(principal, {**(query or {}), "published": {"$ne": False}})


@lru_cache(maxsize=4)
def jwks_client(issuer: str):
    return jwt.PyJWKClient(issuer.rstrip("/") + "/.well-known/jwks.json", timeout=5, lifespan=300)


@lru_cache(maxsize=2)
def offline_keys(url: str):
    return jwt.PyJWKClient(url, timeout=5, lifespan=300)


def verify_offline(token, settings):
    if not (
        settings.offline_issuer.startswith("https://")
        and settings.offline_jwks_url
        and settings.pilot_org_id
    ):
        raise HTTPException(503, "Local identity service is not configured")
    try:
        key = offline_keys(settings.offline_jwks_url).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=settings.offline_issuer,
            audience="secure-smtp-api",
            options={"require": ["sub", "exp", "iat", "azp"]},
        )
    except jwt.PyJWKClientConnectionError:
        raise HTTPException(503, "Local identity service unavailable") from None
    except (jwt.PyJWTError, ValueError, TypeError):
        raise HTTPException(401, "Invalid or expired local session") from None
    if claims["azp"] != "secure-smtp" or claims.get("typ") != "Bearer":
        raise HTTPException(403, "Invalid application session")
    resources = claims.get("resource_access")
    client_roles = resources.get("secure-smtp") if isinstance(resources, dict) else None
    roles = client_roles.get("roles") if isinstance(client_roles, dict) else None
    if (
        not isinstance(roles, list)
        or not all(isinstance(role, str) for role in roles)
        or not {"admin", "analyst"}.intersection(roles)
    ):
        raise HTTPException(403, "A Secure SMTP role is required")
    return Principal(
        claims["sub"],
        settings.pilot_org_id,
        "admin" if "admin" in roles else "member",
        int(claims["exp"]),
    )


def verify_token(token: str) -> Principal:
    if not token or len(token) > 16384:
        raise HTTPException(401, "Invalid session", headers={"WWW-Authenticate": "Bearer"})

    # 1. Native MongoDB Authentication JWT check
    try:
        payload = jwt.decode(
            token, get_jwt_secret(), algorithms=["HS256"], issuer="secure-smtp-native"
        )
        return Principal(
            user_id=payload["sub"],
            org_id=payload.get("org_id", "pilot"),
            role=payload.get("role", "admin"),
            expires_at=int(payload.get("exp", 0)),
        )
    except jwt.PyJWTError:
        pass

    settings = get_settings()
    if getattr(settings, "auth_provider", "clerk") == "keycloak":
        return verify_offline(token, settings)
    if not (
        settings.clerk_issuer.startswith("https://")
        and (getattr(settings, "public_registration", False) or settings.pilot_org_id)
        and settings.clerk_authorized_parties
    ):
        raise HTTPException(401, "Invalid or expired session", headers={"WWW-Authenticate": "Bearer"})
    try:
        key = jwks_client(settings.clerk_issuer).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=settings.clerk_issuer,
            audience=settings.clerk_audience or None,
            options={
                "require": ["exp", "nbf", "iat", "iss", "sub", "sid", "azp"],
                "verify_aud": bool(settings.clerk_audience),
            },
            leeway=5,
        )
    except jwt.PyJWKClientConnectionError:
        raise HTTPException(503, "Identity verification temporarily unavailable") from None
    except (jwt.PyJWTError, ValueError, TypeError):
        raise HTTPException(
            401, "Invalid or expired session", headers={"WWW-Authenticate": "Bearer"}
        ) from None
    if claims.get("azp") not in settings.clerk_authorized_parties or claims.get("sts") == "pending":
        raise HTTPException(403, "Session is not authorized for this application")
    org = claims.get("o") if claims.get("v") == 2 else None
    org_id = (
        org.get("id")
        if isinstance(org, dict)
        else claims.get("org_id")
        if claims.get("v") != 2
        else None
    )
    role = org.get("rol") if isinstance(org, dict) else claims.get("org_role")
    if not claims.get("sub") or not claims.get("sid"):
        raise HTTPException(403, "A verified session is required")
    if getattr(settings, "public_registration", False) and not org_id:
        # Namespace derives only from the signed identity, never client input.
        return Principal(claims["sub"], "personal:" + claims["sub"], "member", int(claims["exp"]))
    if org_id != settings.pilot_org_id or not claims.get("sub") or not claims.get("sid"):
        raise HTTPException(403, "An active pilot organization membership is required")
    return Principal(
        claims["sub"], org_id, str(role or "").removeprefix("org:"), int(claims["exp"])
    )


async def verify_api_key(
    bearer_creds: HTTPAuthorizationCredentials | None = Depends(http_bearer),
) -> Principal:
    """Legacy dependency name retained; only a verified session Bearer JWT is accepted."""
    if not bearer_creds:
        raise HTTPException(401, "Sign in required", headers={"WWW-Authenticate": "Bearer"})
    return await run_in_threadpool(verify_token, bearer_creds.credentials)


async def require_admin(principal: Principal = Depends(verify_api_key)) -> Principal:
    if principal.role != "admin":
        raise HTTPException(403, "Administrator access required")
    return principal


async def require_lab_admin(principal: Principal = Depends(require_admin)) -> Principal:
    if not get_settings().enable_live_lab:
        raise HTTPException(403, "Controlled mail lab is disabled")
    return principal
