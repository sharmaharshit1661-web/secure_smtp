"""Bounded, owned PCAP assessments; one analysis process per pilot instance."""

import os
import subprocess
import sys
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile

from secure_smtp.api.auth import Principal, scope, verify_api_key
from secure_smtp.config import get_settings
from secure_smtp.db.mongodb import get_jobs_col, get_next_sequence, serialize_doc
from secure_smtp.ingest.validation import validate_capture

router = APIRouter(prefix="/api/analyze", tags=["Analysis"])
_slot = threading.Lock()


def process_job(job_id: str, path: str):
    settings = get_settings()
    try:
        # Hard deadline: a parser cannot hold the web process indefinitely.
        subprocess.run(
            [
                sys.executable,
                "-m",
                "secure_smtp.api.analysis_worker",
                job_id,
                path,
                str(os.getpid()),
            ],
            check=True,
            timeout=settings.analysis_timeout_seconds,
        )
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError):
        get_jobs_col().update_one(
            {"job_id": job_id, "status": {"$in": ["queued", "running"]}},
            {
                "$set": {
                    "status": "failed",
                    "error_message": "Analysis stopped: processing limit or worker failure.",
                    "completed_at": datetime.now(UTC),
                }
            },
        )
    finally:
        Path(path).unlink(missing_ok=True)
        _slot.release()


@router.post("")
async def analyze_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    principal: Principal = Depends(verify_api_key),
) -> dict:
    settings = get_settings()
    ext = Path(file.filename or "").suffix.lower()
    if ext not in (".pcap", ".pcapng"):
        raise HTTPException(400, "Select a PCAP or PCAPNG capture")
    if not _slot.acquire(blocking=False):
        raise HTTPException(
            429,
            "An assessment is already processing. Try again shortly.",
            headers={"Retry-After": "10"},
        )
    job_id = str(uuid.uuid4())
    path = settings.upload_dir / (job_id + ext)
    scheduled = False
    try:
        settings.upload_dir.mkdir(parents=True, exist_ok=True)
        size = 0
        with path.open("xb") as target:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise HTTPException(413, "Capture exceeds the upload limit")
                target.write(chunk)
        try:
            validate_capture(path, settings.max_capture_packets)
        except (ValueError, OSError):
            raise HTTPException(
                400, "Invalid, empty, truncated, or oversized capture. Export a smaller valid PCAP."
            ) from None
        get_jobs_col().insert_one(
            {
                "id": get_next_sequence("job_id"),
                "job_id": job_id,
                "org_id": principal.org_id,
                "owner_id": principal.user_id,
                "pcap_filename": Path(file.filename).name,
                "status": "queued",
                "created_at": datetime.now(UTC),
                "source_kind": "manual_capture",
            }
        )
        background_tasks.add_task(process_job, job_id, str(path))
        scheduled = True
        return {"job_id": job_id, "status": "queued"}
    finally:
        await file.close()
        if not scheduled:
            path.unlink(missing_ok=True)
            _slot.release()


@router.get("/{job_id}/status")
async def get_analysis_status(job_id: str, principal: Principal = Depends(verify_api_key)) -> dict:
    job = get_jobs_col().find_one(scope(principal, {"job_id": job_id}), {"_id": 0})
    if not job:
        raise HTTPException(404, "Job not found")
    return serialize_doc(job)
