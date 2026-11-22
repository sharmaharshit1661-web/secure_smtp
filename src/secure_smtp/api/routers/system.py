"""
System & Health API Router.

Provides unauthenticated status probes and downloads for client demonstration tools.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from secure_smtp.api.auth import require_lab_admin
from secure_smtp.config import get_settings
from secure_smtp.db.mongodb import get_mongo_auth_status

logger = logging.getLogger(__name__)

router = APIRouter(tags=["System"])


@router.get("/api/health")
def health_check() -> dict:
    """Service health check endpoint (unauthenticated for monitoring & status probes)."""
    mongo_status = get_mongo_auth_status()
    is_healthy = mongo_status.get("status") == "connected"
    settings = get_settings()
    if getattr(settings, "auth_provider", "clerk") in ("mongodb", "native"):
        configured = True
    elif getattr(settings, "auth_provider", "clerk") == "keycloak":
        configured = bool(
            settings.offline_issuer and settings.offline_jwks_url and settings.pilot_org_id
        )
    else:
        configured = bool(
            settings.clerk_issuer
            and (getattr(settings, "public_registration", False) or settings.pilot_org_id)
            and settings.clerk_authorized_parties
        )
    if not is_healthy or not configured:
        raise HTTPException(503, "Service not ready")
    return {"status": "healthy", "service": "secure-smtp"}


@router.get("/demo_client.py", include_in_schema=False, dependencies=[Depends(require_lab_admin)])
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


@router.get(
    "/attacker_proxy.py", include_in_schema=False, dependencies=[Depends(require_lab_admin)]
)
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
