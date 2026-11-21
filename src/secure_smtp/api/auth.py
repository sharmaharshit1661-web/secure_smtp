"""Authenticate browser sessions and separately provisioned machine API keys."""

import secrets

from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool

from secure_smtp.config import get_settings

DEFAULT_DEV_API_KEY = "securesmtp_live_secret_key"
AUTH_REQUIRED = get_settings().auth_required


async def authenticate_request(request: Request) -> str:
    from secure_smtp.api.sessions_auth import (
        COOKIE,
        check_origin,
        session_identity,
        verify_clerk_token,
    )

    settings = get_settings()
    authorization = request.headers.get("authorization", "")
    bearer = authorization[7:].strip() if authorization.lower().startswith("bearer ") else None
    if bearer and bearer.count(".") == 2:
        return await run_in_threadpool(verify_clerk_token, bearer)

    cookie = request.cookies.get(COOKIE)
    if cookie:
        identity = session_identity(cookie)
        if not identity:
            raise HTTPException(401, "Session expired. Sign in again.")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            check_origin(request.headers.get("origin"))
        return identity

    # Machine clients use headers. Query-string credentials are deliberately rejected.
    provided = request.headers.get("x-api-key") or bearer
    if not settings.auth_required and not settings.is_production:
        return "anonymous"
    if not provided:
        raise HTTPException(
            401, "Missing API authentication", headers={"WWW-Authenticate": "Bearer"}
        )
    expected = settings.api_key.strip()
    if not expected or (
        settings.is_production and (expected == DEFAULT_DEV_API_KEY or len(expected) < 32)
    ):
        raise HTTPException(503, "API authentication is not configured securely")
    if not secrets.compare_digest(provided.strip(), expected):
        raise HTTPException(403, "Invalid API key. Access denied.")
    return "service-account"


async def verify_api_key(request: Request) -> str:
    """Compatibility dependency used by all protected routers."""
    return await authenticate_request(request)
