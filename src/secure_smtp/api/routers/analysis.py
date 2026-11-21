"""
Analysis & PCAP Ingestion API Router.

Handles PCAP file uploads, background batch processing, and job progress telemetry.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile, status

from secure_smtp.api.auth import verify_api_key
from secure_smtp.api.pipeline import run_pcap_analysis
from secure_smtp.api.ratelimit import rate_limit
from secure_smtp.config import get_settings
from secure_smtp.db.models import AnalysisJob
from secure_smtp.db.mongodb import (
    get_jobs_col,
    get_next_sequence,
    serialize_doc,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analyze", tags=["Analysis"], dependencies=[Depends(verify_api_key)])

# Recognized PCAP/PCAP-NG magic byte signatures
PCAP_MAGIC_SIGNATURES = (
    b"\xd4\xc3\xb2\xa1",  # Standard pcap (little endian microsecond)
    b"\xa1\xb2\xc3\xd4",  # Standard pcap (big endian microsecond)
    b"\x4d\x3c\xb2\xa1",  # Nanosecond pcap (little endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond pcap (big endian)
    b"\x0a\x0d\x0d\x0a",  # PCAP-NG Section Header Block
)

CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks


@router.post("", dependencies=[Depends(rate_limit(max_requests=15, window_seconds=60, scope="analyze_upload"))])
async def analyze_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
) -> dict:
    """Upload a PCAP file for asynchronous cryptographic posture analysis with streaming validation."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    ext = Path(file.filename).suffix.lower()
    if ext not in (".pcap", ".pcapng"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format: {ext}. Expected .pcap or .pcapng",
        )

    settings = get_settings()
    upload_dir = settings.upload_dir
    upload_dir.mkdir(parents=True, exist_ok=True)

    job_id = str(uuid.uuid4())
    pcap_path = upload_dir / f"{job_id}{ext}"
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    total_bytes = 0
    header_bytes = bytearray()

    # Stream file to disk in chunks to avoid memory spikes and validate signatures
    try:
        with open(pcap_path, "wb") as f:
            while chunk := await file.read(CHUNK_SIZE):
                total_bytes += len(chunk)
                if total_bytes > max_bytes:
                    pcap_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Uploaded file exceeds maximum allowable size of {settings.max_upload_size_mb} MB",
                    )
                if len(header_bytes) < 4:
                    needed = 4 - len(header_bytes)
                    header_bytes.extend(chunk[:needed])
                f.write(chunk)
    except HTTPException:
        pcap_path.unlink(missing_ok=True)
        raise
    except Exception as err:
        pcap_path.unlink(missing_ok=True)
        logger.error("Failed to stream upload to disk: %s", err)
        raise HTTPException(status_code=500, detail=f"Failed to save upload: {err}")

    # Validate PCAP magic bytes signature
    if total_bytes < 4 or bytes(header_bytes[:4]) not in PCAP_MAGIC_SIGNATURES:
        pcap_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid capture format: file does not match PCAP or PCAPNG magic signature bytes.",
        )

    # Create analysis job record in MongoDB
    jobs_col = get_jobs_col()
    job = AnalysisJob(
        id=get_next_sequence("job_id"),
        job_id=job_id,
        pcap_filename=file.filename,
        status="queued",
    )
    jobs_col.insert_one(job.model_dump())

    # Start background analysis
    background_tasks.add_task(run_pcap_analysis, job_id, str(pcap_path))

    return {"job_id": job_id, "status": "queued"}


@router.get("/{job_id}/status")
async def get_analysis_status(job_id: str) -> dict:
    """Get the current execution status and error telemetry of an analysis job."""
    jobs_col = get_jobs_col()
    job = jobs_col.find_one({"job_id": job_id}, {"_id": 0})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return serialize_doc(job)
