"""Pilot authentication: provisioned local operator or verified Clerk sessions.

Local sessions deliberately expire on restart. Use one backend worker for this
pilot; a shared session store is required before scaling out.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from functools import lru_cache

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from secure_smtp.api.ratelimit import rate_limit
from secure_smtp.config import get_settings

COOKIE = "secure_smtp_session"
SESSION_TTL = 8 * 60 * 60
_sessions: dict[str, tuple[float, str]] = {}
_tickets: dict[str, tuple[float, str]] = {}
router = APIRouter(prefix="/api/auth", tags=["Authentication"])


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600_000).hex()
    return f"pbkdf2_sha256$600000${salt}${digest}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$")
        rounds = int(iterations)
        if algorithm != "pbkdf2_sha256" or not 600_000 <= rounds <= 2_000_000:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), rounds).hex()
        return hmac.compare_digest(digest, expected)
    except (ValueError, TypeError):
        return False


def check_origin(origin: str | None) -> None:
    # Never trust a user-supplied Host or X-Forwarded-For as an allowlist.
    if not origin or origin not in get_settings().cors_origins:
        raise HTTPException(403, "Request origin is not permitted")


def session_identity(cookie: str | None) -> str | None:
    if not cookie:
        return None
    key = hashlib.sha256(cookie.encode()).hexdigest()
    session = _sessions.get(key)
    if session and session[0] > time.time():
        return session[1]
    _sessions.pop(key, None)
    return None


@lru_cache(maxsize=4)
def jwks_client(issuer: str):
    return jwt.PyJWKClient(issuer.rstrip("/") + "/.well-known/jwks.json", timeout=5)


def verify_clerk_token(token: str) -> str:
    settings = get_settings()
    issuer = settings.clerk_issuer
    if not issuer or not issuer.startswith("https://"):
        raise HTTPException(503, "Clerk authentication is not configured")
    try:
        key = jwks_client(issuer).get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=issuer,
            options={"require": ["exp", "nbf", "iat", "sub", "iss"], "verify_aud": False},
        )
        if claims.get("azp") not in settings.cors_origins or claims.get("sts") == "pending":
            raise HTTPException(403, "Session is not authorized for this application")
        if not claims["sub"]:
            raise HTTPException(401, "Invalid session")
        if settings.clerk_org_id:
            org = claims.get("org_id") or (claims.get("o") or {}).get("id")
            if org != settings.clerk_org_id:
                raise HTTPException(403, "Pilot organization membership required")
        return claims["sub"]
    except jwt.PyJWTError as exc:
        raise HTTPException(401, "Invalid or expired session") from exc


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


@router.post("/login", dependencies=[Depends(rate_limit(5, 60, "login"))])
async def login(data: LoginRequest, request: Request, response: Response):
    check_origin(request.headers.get("origin"))
    settings = get_settings()
    if settings.clerk_issuer or not settings.local_admin_email or not settings.local_password_hash:
        raise HTTPException(503, "Local sign-in is unavailable. Contact your administrator.")
    password_ok = await run_in_threadpool(
        verify_password, data.password, settings.local_password_hash
    )
    email_ok = hmac.compare_digest(
        data.email.strip().lower().encode(), settings.local_admin_email.lower().encode()
    )
    if not (password_ok and email_ok):
        raise HTTPException(401, "Invalid email or password")
    now = time.time()
    for key, session in list(_sessions.items()):
        if session[0] <= now:
            _sessions.pop(key, None)
    if len(_sessions) >= 1000:
        raise HTTPException(503, "Session capacity reached")
    old = request.cookies.get(COOKIE)
    if old:
        _sessions.pop(hashlib.sha256(old.encode()).hexdigest(), None)
    token = secrets.token_urlsafe(32)
    _sessions[hashlib.sha256(token.encode()).hexdigest()] = (
        now + SESSION_TTL,
        settings.local_admin_email,
    )
    response.set_cookie(
        COOKIE,
        token,
        max_age=SESSION_TTL,
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return {"email": settings.local_admin_email, "name": "Pilot operator", "role": "Administrator"}


@router.post("/logout")
async def logout(request: Request, response: Response):
    check_origin(request.headers.get("origin"))
    cookie = request.cookies.get(COOKIE)
    if cookie:
        _sessions.pop(hashlib.sha256(cookie.encode()).hexdigest(), None)
    response.delete_cookie(COOKIE, path="/")
    response.headers["Cache-Control"] = "no-store"
    return {"status": "signed_out"}


# Import only when called to avoid an auth dependency cycle.
async def authenticated(request: Request):
    from secure_smtp.api.auth import authenticate_request

    return await authenticate_request(request)


@router.get("/me")
async def me(response: Response, identity=Depends(authenticated)):
    response.headers["Cache-Control"] = "no-store"
    return {"email": identity, "name": "Pilot operator", "role": "Authenticated operator"}


@router.post("/ws-ticket")
async def websocket_ticket(identity=Depends(authenticated)):
    now = time.time()
    for key, ticket in list(_tickets.items()):
        if ticket[0] <= now:
            _tickets.pop(key, None)
    if len(_tickets) >= 1000:
        raise HTTPException(503, "Connection capacity reached")
    token = secrets.token_urlsafe(32)
    _tickets[token] = (now + 30, identity)
    return {"ticket": token}


def consume_ticket(token: str | None) -> str | None:
    value = _tickets.pop(token, None)
    return value[1] if value and value[0] > time.time() else None
