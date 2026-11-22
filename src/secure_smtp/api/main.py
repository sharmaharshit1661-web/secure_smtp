"""
FastAPI application — Secure SMTP Core Service.

Cryptographic posture intelligence & explainable AI risk attribution for SMTP/IMAP/POP3.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool

from secure_smtp.api.broker import ConnectionManager, get_connection_manager
from secure_smtp.api.pipeline import (
    build_report_data as _build_report_data,
)
from secure_smtp.api.pipeline import (
    generate_job_reports as _generate_reports,
)
from secure_smtp.api.pipeline import (
    run_pcap_analysis as _run_analysis,
)
from secure_smtp.api.routers import (
    analysis_router,
    compliance_router,
    copilot_router,
    hosts_router,
    live_router,
    reports_router,
    sessions_router,
    system_router,
)
from secure_smtp.config import get_settings
from secure_smtp.db.mongodb import (
    get_hosts_col,
    get_jobs_col,
    get_sessions_col,
    init_db_indexes,
)

logger = logging.getLogger(__name__)


# ── Application Lifespan Handler ──

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup initialization and graceful shutdown."""
    logger.info("Initializing Secure SMTP database indexes and services...")
    init_db_indexes()

    # Single-instance pilot recovery: interrupted jobs are visible failures, never false success.
    get_jobs_col().update_many({"status": {"$in": ["queued", "running"]}}, {"$set": {"status": "failed", "error_message": "Backend restarted during analysis. Upload the capture again."}})

    # Complete the publication step if the process stopped after report completion.
    from secure_smtp.monitoring.service import refresh_hosts
    for job in get_jobs_col().find({"status": "done"}):
        query = {"job_id": job.get("job_id"), "published": False}
        if job.get("org_id"):
            query["org_id"] = job["org_id"]
        get_sessions_col().update_many(query, {"$set": {"published": True}})
    if get_settings().pilot_org_id:
        refresh_hosts(get_settings().pilot_org_id)

    # Ensure upload and reports directories exist
    settings = get_settings()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    # Uploaded capture bytes have no retention purpose once their process is gone.
    for interrupted in get_jobs_col().find({"status": "failed"}):
        for capture in settings.upload_dir.glob(interrupted["job_id"] + ".*"):
            capture.unlink(missing_ok=True)

    # Auto-start Live Mail Lab on all 4 ports if enabled
    if settings.enable_live_lab:
        try:
            from secure_smtp.live.mail_server import get_live_lab

            lab = get_live_lab()
            if not lab.is_running:
                await lab.start()
                logger.info("Live Mail Lab auto-started on 0.0.0.0 ports 2525, 2526, 2527, 2528")
        except Exception as lab_err:
            logger.warning("Could not auto-start Live Mail Lab: %s", lab_err)
    else:
        logger.info("Live Mail Lab is disabled by configuration (SECURE_SMTP_ENABLE_LIVE_LAB=false).")

    async def maintenance():
        from secure_smtp.db.mongodb import get_database
        from secure_smtp.operations.lifecycle import enforce_retention
        while True:
            if settings.pilot_org_id:
                try:
                    deleted = await run_in_threadpool(enforce_retention, settings.pilot_org_id)
                    status = {"status": "healthy", "deleted": deleted}
                except Exception:
                    status = {"status": "failed", "error": "Retention cleanup failed; administrator review required"}
                try:
                    await run_in_threadpool(lambda: get_database().operations.update_one(
                        {"org_id": settings.pilot_org_id, "kind": "retention"},
                        {"$set": {**status, "checked_at": datetime.now(UTC)}}, upsert=True))
                except Exception:
                    logger.error("Retention status could not be persisted")
            await asyncio.sleep(3600)
    maintenance_task = asyncio.create_task(maintenance())
    try:
        yield
    finally:
        maintenance_task.cancel()
        try:
            await maintenance_task
        except asyncio.CancelledError:
            pass

    logger.info("Shutting down Secure SMTP services...")
    try:
        from secure_smtp.live.mail_server import get_live_lab

        lab = get_live_lab()
        if lab.is_running:
            await lab.stop()
    except Exception as stop_err:
        logger.debug("Error stopping Live Mail Lab: %s", stop_err)


# ── App Setup ──

app = FastAPI(
    title="Secure SMTP",
    description="Passive Cryptographic Posture Intelligence & Explainable AI Risk Attribution for SMTP / IMAP / POP3",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None, redoc_url=None, openapi_url=None,
)

# ── Configuration & CORS ──

settings = get_settings()

DEFAULT_CORS_ORIGINS = settings.cors_origins
allowed_origins = settings.cors_origins

# If wildcard is explicitly used, credentials must be False per W3C CORS specification
allow_credentials = False if "*" in allowed_origins else True
allowed_headers = settings.cors_headers

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=allow_credentials,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"],
    allow_headers=allowed_headers,
    expose_headers=["Content-Disposition", "Content-Length", "X-Total-Count"],
    max_age=600,
)

UPLOAD_DIR = settings.upload_dir
REPORTS_DIR = settings.reports_dir


# ── Register Domain Routers ──

from secure_smtp.api.routers.agents import router as agents_router

app.include_router(agents_router)
from secure_smtp.api.routers.operations import router as operations_router

app.include_router(operations_router)
app.include_router(system_router)
app.include_router(analysis_router)
app.include_router(hosts_router)
app.include_router(sessions_router)
app.include_router(reports_router)
app.include_router(compliance_router)
app.include_router(copilot_router)
app.include_router(live_router)


# ── Backward-Compatibility Re-exports ──
__all__ = [
    "app",
    "DEFAULT_CORS_ORIGINS",
    "UPLOAD_DIR",
    "REPORTS_DIR",
    "_run_analysis",
    "_generate_reports",
    "_build_report_data",
    "ConnectionManager",
    "get_connection_manager",
    "get_sessions_col",
    "get_hosts_col",
    "get_jobs_col",
]


class UploadBodyLimit:
    """Enforce a byte ceiling before multipart parsing, including chunked requests."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or not scope.get('path', '').startswith('/api/'):
            return await self.app(scope, receive, send)
        from fastapi import HTTPException
        total = 0
        async def bounded_receive():
            nonlocal total
            message = await receive()
            total += len(message.get('body', b''))
            limit = get_settings().max_upload_bytes + 65536 if scope.get('path') == '/api/analyze' else 524288
            if total > limit:
                raise HTTPException(413, 'Upload exceeds request size limit')
            return message
        return await self.app(scope, bounded_receive, send)


app.add_middleware(UploadBodyLimit)
