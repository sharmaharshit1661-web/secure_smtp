"""
FastAPI application — Secure SMTP Core Service.

Cryptographic posture intelligence & explainable AI risk attribution for SMTP/IMAP/POP3.
"""

from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from secure_smtp.api.broker import ConnectionManager, get_connection_manager
from secure_smtp.api.pipeline import (
    build_report_data as _build_report_data,
    generate_job_reports as _generate_reports,
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
    settings = get_settings()

    # Fail-fast check for default development secrets in production
    if settings.is_production and settings.auth_required:
        if settings.api_key == "securesmtp_live_secret_key":
            logger.critical(
                "FATAL CONFIGURATION: Insecure default development API key detected in production mode. "
                "Set SECURE_SMTP_API_KEY environment variable to a secure secret."
            )
            raise RuntimeError(
                "Refusing to start in production mode (SECURE_SMTP_ENV=production) with default development API key."
            )

    logger.info("Initializing Secure SMTP database indexes and services...")
    init_db_indexes()

    # Ensure upload and reports directories exist
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.reports_dir.mkdir(parents=True, exist_ok=True)

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

    yield

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
    expose_headers=["Content-Disposition", "Content-Length", "X-Total-Count", "X-Request-ID"],
    max_age=600,
)


@app.middleware("http")
async def security_and_tracing_middleware(request: Request, call_next):
    """
    Enterprise security headers and request tracing middleware.
    Appends unique X-Request-ID and defense-in-depth security response headers.
    """
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id

    response = await call_next(request)

    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    return response

UPLOAD_DIR = settings.upload_dir
REPORTS_DIR = settings.reports_dir


# ── Register Domain Routers ──

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
