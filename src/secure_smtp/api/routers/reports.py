"""
Reports Download API Router.

Serves executive and technical compliance reports in JSON, HTML, and PDF formats.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse

from secure_smtp.api.auth import verify_api_key
from secure_smtp.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/reports", tags=["Reports"], dependencies=[Depends(verify_api_key)])

SAFE_JOB_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]+$")


def _get_verified_report_path(job_id: str, filename: str) -> Path:
    """
    Validate job_id format and ensure target file resides strictly within reports_dir,
    preventing directory traversal attacks (e.g., ../../../etc/passwd).
    """
    if not SAFE_JOB_ID_REGEX.match(job_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid job identifier format. Only alphanumeric characters, dashes, and underscores permitted.",
        )

    settings = get_settings()
    base_dir = settings.reports_dir.resolve()
    target_path = (base_dir / job_id / filename).resolve()

    if not target_path.is_relative_to(base_dir):
        logger.warning("Path traversal attempt blocked for job_id=%s, file=%s", job_id, filename)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: path traversal attempt detected.",
        )

    if not target_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    return target_path


@router.get("/{job_id}.json")
async def get_json_report(job_id: str) -> FileResponse:
    """Download technical JSON assessment report with path traversal safeguards."""
    report_path = _get_verified_report_path(job_id, "report.json")
    return FileResponse(
        str(report_path),
        media_type="application/json",
        filename=f"secure_smtp_report_{job_id}.json",
    )


@router.get("/{job_id}.pdf")
async def get_pdf_report(job_id: str) -> FileResponse:
    """Download executive PDF assessment report with path traversal safeguards."""
    report_path = _get_verified_report_path(job_id, "report.pdf")
    return FileResponse(
        str(report_path),
        media_type="application/pdf",
        filename=f"secure_smtp_report_{job_id}.pdf",
    )


@router.get("/{job_id}.html")
async def get_html_report(job_id: str) -> FileResponse:
    """Download standalone HTML assessment report with path traversal safeguards."""
    report_path = _get_verified_report_path(job_id, "report.html")
    return FileResponse(
        str(report_path),
        media_type="text/html",
        filename=f"secure_smtp_report_{job_id}.html",
    )
