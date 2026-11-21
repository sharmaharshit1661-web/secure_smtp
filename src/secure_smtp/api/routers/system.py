"""
System & Health API Router.

Provides unauthenticated status probes and downloads for client demonstration tools.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from secure_smtp.api.auth import AUTH_REQUIRED
from secure_smtp.db.mongodb import get_mongo_auth_status

logger = logging.getLogger(__name__)

router = APIRouter(tags=["System"])


@router.get("/api/health")
def health_check() -> dict:
    """Service health check endpoint (unauthenticated for monitoring & status probes)."""
    mongo_status = get_mongo_auth_status()
    is_healthy = mongo_status.get("status") == "connected"
    return {
        "status": "healthy" if is_healthy else "degraded",
        "service": "secure-smtp",
        "version": "0.1.0",
        "auth": {
            "api_auth": {
                "enabled": AUTH_REQUIRED,
                "scheme": "X-API-Key / Bearer / Query",
            },
            "mongodb_auth": {
                "enabled": mongo_status.get("auth_enabled", False),
                "required": mongo_status.get("auth_required", False),
                "user": mongo_status.get("authenticated_user"),
                "auth_source": mongo_status.get("auth_source"),
            },
        },
        "database": {
            "status": mongo_status.get("status"),
            "database": mongo_status.get("database"),
            "ping": mongo_status.get("ping", False),
            "uri_masked": mongo_status.get("uri_masked"),
        },
    }


@router.get("/demo_client.py", include_in_schema=False)
def download_demo_client() -> FileResponse:
    """Allow remote laptops on the LAN to download the test script directly."""
    demo_script_path = Path(__file__).resolve().parents[4] / "demo_client.py"
    if not demo_script_path.exists():
        demo_script_path = Path("demo_client.py").resolve()
    if not demo_script_path.exists():
        raise HTTPException(status_code=404, detail="demo_client.py not found on server")
    return FileResponse(
        path=demo_script_path,
        media_type="text/x-python",
        filename="demo_client.py",
    )


@router.get("/attacker_proxy.py", include_in_schema=False)
def download_attacker_proxy() -> FileResponse:
    """Allow 2nd laptop (interceptor node) to download the MitM proxy script directly."""
    proxy_script_path = Path(__file__).resolve().parents[4] / "attacker_proxy.py"
    if not proxy_script_path.exists():
        proxy_script_path = Path("attacker_proxy.py").resolve()
    if not proxy_script_path.exists():
        raise HTTPException(status_code=404, detail="attacker_proxy.py not found on server")
    return FileResponse(
        path=proxy_script_path,
        media_type="text/x-python",
        filename="attacker_proxy.py",
    )
