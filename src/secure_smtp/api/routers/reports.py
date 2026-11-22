"""Download only completed assessments owned by the authenticated organization."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from secure_smtp.api.auth import Principal, scope, verify_api_key
from secure_smtp.config import get_settings
from secure_smtp.db.mongodb import get_jobs_col

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("/{job_id}.{format}")
async def get_report(
    job_id: UUID, format: str, principal: Principal = Depends(verify_api_key)
) -> FileResponse:
    media = {"json": "application/json", "pdf": "application/pdf", "html": "text/html"}
    if format not in media:
        raise HTTPException(404, "Report not found")
    job = get_jobs_col().find_one(scope(principal, {"job_id": str(job_id), "status": "done"}))
    path = get_settings().reports_dir / str(job_id) / ("report." + format)
    if not job or not path.is_file():
        raise HTTPException(404, "Completed report not found")
    return FileResponse(
        path,
        media_type=media[format],
        filename=f"secure_smtp_{job_id}.{format}",
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "sandbox; default-src 'none'; style-src 'unsafe-inline'",
        },
    )
