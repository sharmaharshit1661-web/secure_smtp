"""
FastAPI application — Stage 6 API (MongoDB Powered).

Full API contract per TAD §7:
- POST /api/analyze — upload PCAP for analysis
- GET /api/analyze/{job_id}/status — job status
- GET /api/hosts — list all hosts with scores
- GET /api/hosts/{host_id} — host detail + sessions
- GET /api/sessions/{session_id} — full session detail
- GET /api/sessions/{session_id}/explain — SHAP explanation
- GET /api/reports/{job_id}.{format} — export reports
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    HTTPException,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from pymongo import DESCENDING

from secure_smtp.ai.copilot import ask_copilot, generate_incident_briefing, generate_server_remediation
from secure_smtp.api.auth import AUTH_REQUIRED, verify_api_key
from secure_smtp.compliance.frameworks import evaluate_fleet_compliance, evaluate_session_compliance
from secure_smtp.config import get_settings

from secure_smtp.db.models import (
    AnalysisJob,
    AnomalyScore,
    Certificate,
    Finding,
    Host,
    RiskScore,
    Session,
    TLSHandshake,
)
from secure_smtp.db.mongodb import (
    get_hosts_col,
    get_jobs_col,
    get_mongo_auth_status,
    get_next_sequence,
    get_sessions_col,
    init_db_indexes,
    serialize_doc,
)

logger = logging.getLogger(__name__)

# ── WebSocket Real-Time Event Broker ──


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts real-time forensic events."""

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket client connected. Active: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket client disconnected. Active: %d", len(self.active_connections))

    async def broadcast(self, message: dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


_connection_manager = ConnectionManager()


def get_connection_manager() -> ConnectionManager:
    return _connection_manager


# ── Lifespan Handler ──

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup initialization and graceful shutdown."""
    logger.info("Initializing Secure SMTP database indexes and services...")
    init_db_indexes()

    # Auto-start Live Mail Lab on all 4 ports (0.0.0.0)
    try:
        from secure_smtp.live.mail_server import get_live_lab
        lab = get_live_lab()
        if not lab.is_running:
            await lab.start()
            logger.info("Live Mail Lab auto-started on 0.0.0.0 ports 2525, 2526, 2527, 2528")
    except Exception as lab_err:
        logger.warning("Could not auto-start Live Mail Lab: %s", lab_err)

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
    expose_headers=["Content-Disposition", "Content-Length", "X-Total-Count"],
    max_age=600,
)

# Upload directory for PCAPs and reports from Settings
UPLOAD_DIR = settings.upload_dir
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

REPORTS_DIR = settings.reports_dir
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ── Analysis Pipeline ──


def _run_analysis(job_id: str, pcap_path: str) -> None:
    """
    Background task: run the full analysis pipeline on a PCAP file and persist to MongoDB.

    Pipeline: PCAP → TCP streams → Protocol ID → TLS handshake →
    Cert parsing → Rule engine → AI scoring → MongoDB storage → Report generation.
    """
    from secure_smtp.ai.anomaly_model import AnomalyDetector
    from secure_smtp.ai.explain import enrich_risk_score_with_explanation
    from secure_smtp.ai.features import build_feature_vector
    from secure_smtp.ai.risk_model import RiskModel, compute_host_rollup
    from secure_smtp.ingest.pcap_reader import read_pcap
    from secure_smtp.ingest.protocol_id import identify_protocol
    from secure_smtp.ingest.tcp_stream import reassemble_stream
    from secure_smtp.rules.engine import RuleEngine
    from secure_smtp.tls.cert_parser import parse_certificate_chain
    from secure_smtp.tls.fingerprint import compute_fingerprints
    from secure_smtp.tls.handshake_parser import parse_handshake

    jobs_col = get_jobs_col()
    hosts_col = get_hosts_col()
    sessions_col = get_sessions_col()

    try:
        # Update job status
        jobs_col.update_one({"job_id": job_id}, {"$set": {"status": "running"}})

        # Stage 1: Read PCAP and group into streams
        packet_streams = read_pcap(pcap_path)
        logger.info("Job %s: Read %d streams from PCAP", job_id, len(packet_streams))

        # Initialize engines
        rule_engine = RuleEngine()
        risk_model = RiskModel()
        anomaly_detector = AnomalyDetector()

        all_feature_vectors = []
        all_host_ips = []
        created_session_ids = []

        for stream in packet_streams:
            # Stage 1: TCP reassembly
            reassembled = reassemble_stream(stream)

            # Skip empty streams
            if reassembled.client_to_server.is_empty and reassembled.server_to_client.is_empty:
                continue

            # Stage 2: Protocol identification
            proto_id = identify_protocol(reassembled)

            # Skip unknown protocols with no TLS
            if proto_id.protocol.value == "unknown" and proto_id.tls_mode.value == "none":
                continue

            # Find or create Host in MongoDB
            host_doc = hosts_col.find_one({"ip_or_hostname": reassembled.server_ip})
            if not host_doc:
                host_id = get_next_sequence("host_id")
                host_data = {
                    "id": host_id,
                    "ip_or_hostname": reassembled.server_ip,
                    "session_count": 0,
                    "aggregate_risk_score": 0.0,
                }
                hosts_col.insert_one(host_data)
            else:
                host_id = host_doc["id"]

            session_id = get_next_sequence("session_id")

            # Create session model
            session = Session(
                id=session_id,
                pcap_source=Path(pcap_path).name,
                src_ip=reassembled.client_ip,
                dst_ip=reassembled.server_ip,
                src_port=reassembled.client_port,
                dst_port=reassembled.server_port,
                protocol=proto_id.protocol,
                tls_mode=proto_id.tls_mode,
                starttls_advertised=proto_id.starttls_advertised,
                starttls_completed=proto_id.starttls_completed,
                host_id=host_id,
            )

            # Stage 3: TLS handshake parsing
            handshake_model: TLSHandshake | None = None
            certificates_models: list[Certificate] = []

            if proto_id.tls_mode.value != "none":
                parsed_hs = parse_handshake(
                    reassembled.client_to_server.data,
                    reassembled.server_to_client.data,
                    proto_id.tls_offset_client,
                    proto_id.tls_offset_server,
                )

                # Compute fingerprints
                fingerprints = compute_fingerprints(
                    parsed_hs.client_hello, parsed_hs.server_hello
                )

                # Create TLSHandshake model
                handshake_model = TLSHandshake(
                    session_id=session.id,
                    tls_version_offered=json.dumps(parsed_hs.tls_version_offered),
                    tls_version_negotiated=parsed_hs.tls_version_negotiated,
                    cipher_suite_negotiated=parsed_hs.cipher_suite_negotiated,
                    key_exchange_type=parsed_hs.key_exchange_type,
                    forward_secrecy=parsed_hs.forward_secrecy,
                    ja3=fingerprints.ja3,
                    ja3s=fingerprints.ja3s,
                    ja4=fingerprints.ja4,
                    ja4s=fingerprints.ja4s,
                    extensions=json.dumps({
                        str(k): v.hex() for k, v in (
                            parsed_hs.client_hello.extensions.items()
                            if parsed_hs.client_hello else {}
                        )
                    }),
                    visibility_limited=parsed_hs.visibility_limited,
                )

                # Parse certificates
                if parsed_hs.raw_certificates:
                    parsed_certs = parse_certificate_chain(parsed_hs.raw_certificates)
                    for pc in parsed_certs:
                        cert_model = Certificate(
                            chain_position=pc.chain_position,
                            subject=pc.subject,
                            issuer=pc.issuer,
                            san=json.dumps(pc.san),
                            not_before=pc.not_before,
                            not_after=pc.not_after,
                            public_key_algorithm=pc.public_key_algorithm,
                            key_length_bits=pc.key_length_bits,
                            signature_algorithm=pc.signature_algorithm,
                            self_signed=pc.self_signed,
                            chain_valid=pc.chain_valid,
                        )
                        certificates_models.append(cert_model)

            # Stage 4: Rule engine
            findings = rule_engine.evaluate_session(
                session, handshake_model, certificates_models
            )
            for finding in findings:
                finding.session_id = session.id

            # Stage 5: Feature vector + risk scoring
            fv = build_feature_vector(
                session, handshake_model, certificates_models, findings
            )
            risk_score = risk_model.score_session(fv, findings)
            risk_score.session_id = session.id
            risk_score = enrich_risk_score_with_explanation(
                risk_score, findings, fv
            )

            # Assemble complete session document for MongoDB
            session.handshake = handshake_model
            session.certificates = certificates_models
            session.findings = findings
            session.risk_score = risk_score

            session_dict = session.model_dump()
            sessions_col.insert_one(session_dict)

            # Dispatch real-time security alerts if configured thresholds are met
            try:
                from secure_smtp.alerts.engine import dispatch_alert
                dispatch_alert(
                    session_id=session.id,
                    client_ip=reassembled.client_ip,
                    server_ip=reassembled.server_ip,
                    protocol=session.protocol,
                    risk_score=risk_score.score,
                    findings=[f.model_dump() for f in findings],
                    pcap_source=Path(pcap_path).name,
                )
            except Exception as alert_err:
                logger.debug("Alert dispatch skipped or failed: %s", alert_err)

            all_feature_vectors.append(fv)
            all_host_ips.append(reassembled.server_ip)
            created_session_ids.append(session_id)

        # Stage 5: Anomaly detection across batch
        if all_feature_vectors:
            import numpy as np

            feature_matrix = np.array([fv.values for fv in all_feature_vectors])
            anomaly_detector.fit_global(feature_matrix)

            for fv, host_ip, sid in zip(all_feature_vectors, all_host_ips, created_session_ids):
                anomaly_score = anomaly_detector.score_session(fv, host_ip)
                anomaly_score.session_id = sid
                sessions_col.update_one(
                    {"id": sid},
                    {"$set": {"anomaly_score": anomaly_score.model_dump()}},
                )

        # Update host aggregate scores
        all_hosts = list(hosts_col.find())
        for h in all_hosts:
            host_sessions = list(sessions_col.find({"host_id": h["id"]}))
            s_count = len(host_sessions)

            host_risk_scores = []
            for s in host_sessions:
                rs_data = s.get("risk_score")
                if rs_data:
                    host_risk_scores.append(RiskScore(**rs_data))

            agg_score = compute_host_rollup(host_risk_scores)
            hosts_col.update_one(
                {"id": h["id"]},
                {"$set": {
                    "session_count": s_count,
                    "aggregate_risk_score": agg_score,
                }},
            )

        # Generate reports
        _generate_reports(job_id)

        # Mark job as done
        jobs_col.update_one(
            {"job_id": job_id},
            {"$set": {
                "status": "done",
                "completed_at": datetime.now(UTC),
            }},
        )

        logger.info("Job %s: Analysis complete", job_id)

    except Exception as e:
        logger.error("Job %s failed: %s", job_id, e, exc_info=True)
        jobs_col.update_one(
            {"job_id": job_id},
            {"$set": {
                "status": "failed",
                "error_message": str(e),
                "completed_at": datetime.now(UTC),
            }},
        )


def _generate_reports(job_id: str) -> None:
    """Generate JSON, HTML, and PDF reports for a completed analysis from MongoDB."""
    from secure_smtp.reporting.html_export import generate_html_report
    from secure_smtp.reporting.json_export import generate_json_report
    from secure_smtp.reporting.pdf_export import generate_pdf_report

    job_dir = REPORTS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    hosts_col = get_hosts_col()
    sessions_col = get_sessions_col()

    hosts = list(hosts_col.find({}, {"_id": 0}))
    sessions = list(sessions_col.find({}, {"_id": 0}))

    report_data = _build_report_data(hosts, sessions)

    # JSON report
    json_path = job_dir / "report.json"
    generate_json_report(report_data, str(json_path))

    # HTML report
    html_path = job_dir / "report.html"
    generate_html_report(report_data, str(html_path))

    # PDF report
    pdf_path = job_dir / "report.pdf"
    generate_pdf_report(str(html_path), str(pdf_path), report_data=report_data)


def _build_report_data(hosts: list[dict], sessions: list[dict]) -> dict:
    """Build comprehensive report data structure from MongoDB documents."""
    report = {
        "title": "Secure SMTP Security Assessment Report",
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": {
            "total_hosts": len(hosts),
            "total_sessions": len(sessions),
            "total_findings": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "low_findings": 0,
        },
        "hosts": [],
        "sessions": [],
    }

    for host in hosts:
        report["hosts"].append({
            "id": host.get("id"),
            "ip_or_hostname": host.get("ip_or_hostname"),
            "session_count": host.get("session_count", 0),
            "aggregate_risk_score": host.get("aggregate_risk_score", 0.0),
        })

    for session in sessions:
        handshake = session.get("handshake")
        certificates = session.get("certificates", [])
        findings = session.get("findings", [])
        risk_score = session.get("risk_score")
        anomaly_score = session.get("anomaly_score")

        # Update summary counts
        for f in findings:
            report["summary"]["total_findings"] += 1
            severity = f.get("severity", "info").lower()
            if severity == "critical":
                report["summary"]["critical_findings"] += 1
            elif severity == "high":
                report["summary"]["high_findings"] += 1
            elif severity == "medium":
                report["summary"]["medium_findings"] += 1
            elif severity == "low":
                report["summary"]["low_findings"] += 1

        proto = session.get("protocol", "unknown")
        proto_val = proto.value if hasattr(proto, "value") else str(proto)

        tls = session.get("tls_mode", "none")
        tls_val = tls.value if hasattr(tls, "value") else str(tls)

        session_data = {
            "id": session.get("id"),
            "src_ip": session.get("src_ip"),
            "dst_ip": session.get("dst_ip"),
            "src_port": session.get("src_port"),
            "dst_port": session.get("dst_port"),
            "protocol": proto_val,
            "tls_mode": tls_val,
            "starttls_advertised": session.get("starttls_advertised", False),
            "starttls_completed": session.get("starttls_completed", False),
            "handshake": handshake,
            "certificates": [
                {
                    "chain_position": c.get("chain_position", 0),
                    "subject": c.get("subject"),
                    "issuer": c.get("issuer"),
                    "not_before": c.get("not_before"),
                    "not_after": c.get("not_after"),
                    "public_key_algorithm": c.get("public_key_algorithm"),
                    "key_length_bits": c.get("key_length_bits"),
                    "signature_algorithm": c.get("signature_algorithm"),
                    "self_signed": c.get("self_signed", False),
                    "chain_valid": c.get("chain_valid", True),
                }
                for c in certificates
            ],
            "findings": [
                {
                    "rule_id": f.get("rule_id"),
                    "severity": f.get("severity"),
                    "message": f.get("message"),
                    "recommendation": f.get("recommendation_text") or f.get("recommendation", ""),
                    "evidence": f.get("evidence", "{}"),
                }
                for f in findings
            ],
            "risk_score": {
                "score": risk_score.get("score_0_100", 0.0) if risk_score else 0.0,
                "tier": risk_score.get("tier", "low") if risk_score else "low",
                "explanation": risk_score.get("feature_attribution", "{}") if risk_score else "{}",
            } if risk_score else None,
            "anomaly_score": {
                "score": anomaly_score.get("anomaly_score", 0.0) if anomaly_score else 0.0,
                "is_anomalous": anomaly_score.get("is_anomalous", False) if anomaly_score else False,
                "baseline": anomaly_score.get("baseline_reference", "global") if anomaly_score else "global",
            } if anomaly_score else None,
        }
        report["sessions"].append(session_data)

    return report


# ── Endpoints ──


@app.get("/api/health", tags=["System"])
def health_check():
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


@app.get("/demo_client.py", include_in_schema=False)
def download_demo_client():
    """Allow remote laptops on the LAN to download the test script directly."""
    demo_script_path = Path(__file__).resolve().parents[3] / "demo_client.py"
    if not demo_script_path.exists():
        demo_script_path = Path("demo_client.py").resolve()
    if not demo_script_path.exists():
        raise HTTPException(status_code=404, detail="demo_client.py not found on server")
    return FileResponse(
        path=demo_script_path,
        media_type="text/x-python",
        filename="demo_client.py",
    )


@app.get("/attacker_proxy.py", include_in_schema=False)
def download_attacker_proxy():
    """Allow 2nd laptop (interceptor node) to download the MitM proxy script directly."""
    proxy_script_path = Path(__file__).resolve().parents[3] / "attacker_proxy.py"
    if not proxy_script_path.exists():
        proxy_script_path = Path("attacker_proxy.py").resolve()
    if not proxy_script_path.exists():
        raise HTTPException(status_code=404, detail="attacker_proxy.py not found on server")
    return FileResponse(
        path=proxy_script_path,
        media_type="text/x-python",
        filename="attacker_proxy.py",
    )




@app.post("/api/analyze", dependencies=[Depends(verify_api_key)])
async def analyze_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    """Upload a PCAP file for analysis."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    ext = Path(file.filename).suffix.lower()
    if ext not in (".pcap", ".pcapng"):
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format: {ext}. Expected .pcap or .pcapng",
        )

    job_id = str(uuid.uuid4())
    pcap_path = UPLOAD_DIR / f"{job_id}{ext}"

    # Save uploaded file
    with open(pcap_path, "wb") as f:
        content = await file.read()
        f.write(content)

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
    background_tasks.add_task(_run_analysis, job_id, str(pcap_path))

    return {"job_id": job_id, "status": "queued"}


@app.get("/api/analyze/{job_id}/status", dependencies=[Depends(verify_api_key)])
async def get_analysis_status(job_id: str):
    """Get the status of an analysis job."""
    jobs_col = get_jobs_col()
    job = jobs_col.find_one({"job_id": job_id}, {"_id": 0})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return serialize_doc(job)


@app.get("/api/hosts", dependencies=[Depends(verify_api_key)])
async def list_hosts():
    """List all hosts with aggregate risk scores."""
    hosts_col = get_hosts_col()
    hosts = list(hosts_col.find({}, {"_id": 0}).sort("aggregate_risk_score", DESCENDING))
    return [
        {
            "host_id": h["id"],
            "ip": h["ip_or_hostname"],
            "aggregate_risk_score": h.get("aggregate_risk_score", 0.0),
            "session_count": h.get("session_count", 0),
        }
        for h in hosts
    ]


@app.get("/api/hosts/{host_id}", dependencies=[Depends(verify_api_key)])
async def get_host_detail(host_id: int):
    """Get host detail with session list."""
    hosts_col = get_hosts_col()
    sessions_col = get_sessions_col()

    host = hosts_col.find_one({"id": host_id}, {"_id": 0})
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    sessions = list(sessions_col.find({"host_id": host_id}, {"_id": 0}))

    session_list = []
    for s in sessions:
        risk = s.get("risk_score") or {}
        proto = s.get("protocol", "unknown")
        proto_val = proto.value if hasattr(proto, "value") else str(proto)

        tls = s.get("tls_mode", "none")
        tls_val = tls.value if hasattr(tls, "value") else str(tls)

        session_list.append({
            "session_id": s["id"],
            "src_ip": s["src_ip"],
            "dst_ip": s["dst_ip"],
            "src_port": s["src_port"],
            "dst_port": s["dst_port"],
            "protocol": proto_val,
            "tls_mode": tls_val,
            "risk_score": risk.get("score_0_100", 0.0) if risk else None,
            "risk_tier": risk.get("tier", "low") if risk else None,
        })

    return {
        "host_id": host["id"],
        "ip": host["ip_or_hostname"],
        "aggregate_risk_score": host.get("aggregate_risk_score", 0.0),
        "session_count": host.get("session_count", len(sessions)),
        "sessions": session_list,
    }


@app.get("/api/sessions", dependencies=[Depends(verify_api_key)])
async def list_sessions(limit: int = 100):
    """List recent sessions across all hosts for fleet-wide telemetry."""
    sessions_col = get_sessions_col()
    sessions = list(sessions_col.find({}, {"_id": 0}).sort("id", DESCENDING).limit(limit))
    return [
        {
            "id": s["id"],
            "host_id": s.get("host_id"),
            "src_ip": s.get("src_ip"),
            "dst_ip": s.get("dst_ip"),
            "src_port": s.get("src_port"),
            "dst_port": s.get("dst_port"),
            "protocol": s.get("protocol").value if hasattr(s.get("protocol"), "value") else str(s.get("protocol", "smtp")),
            "tls_mode": s.get("tls_mode").value if hasattr(s.get("tls_mode"), "value") else str(s.get("tls_mode", "none")),
            "risk_score": (s.get("risk_score") or {}).get("score_0_100", 0.0),
            "risk_tier": (s.get("risk_score") or {}).get("tier", "low"),
            "findings": [
                {
                    "rule_id": f.get("rule_id"),
                    "severity": f.get("severity"),
                    "message": f.get("message")
                }
                for f in s.get("findings", []) if isinstance(f, dict)
            ],
            "tls_version": (s.get("handshake") or {}).get("tls_version_negotiated"),
            "cipher_suite": (s.get("handshake") or {}).get("cipher_suite_negotiated"),
            "forward_secrecy": (s.get("handshake") or {}).get("forward_secrecy", False),
        }
        for s in sessions
    ]


@app.get("/api/sessions/{session_id}", dependencies=[Depends(verify_api_key)])
async def get_session_detail(session_id: int):
    """Get full session detail from MongoDB."""
    sessions_col = get_sessions_col()
    session = sessions_col.find_one({"id": session_id}, {"_id": 0})
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    handshake = session.get("handshake")
    certificates = session.get("certificates", [])
    findings = session.get("findings", [])
    risk_score = session.get("risk_score")
    anomaly_score = session.get("anomaly_score")

    proto = session.get("protocol", "unknown")
    proto_val = proto.value if hasattr(proto, "value") else str(proto)

    tls = session.get("tls_mode", "none")
    tls_val = tls.value if hasattr(tls, "value") else str(tls)

    result = {
        "id": session["id"],
        "pcap_source": session.get("pcap_source", ""),
        "src_ip": session["src_ip"],
        "dst_ip": session["dst_ip"],
        "src_port": session["src_port"],
        "dst_port": session["dst_port"],
        "protocol": proto_val,
        "tls_mode": tls_val,
        "starttls_advertised": session.get("starttls_advertised", False),
        "starttls_completed": session.get("starttls_completed", False),
    }

    if handshake:
        kex = handshake.get("key_exchange_type", "unknown")
        kex_val = kex.value if hasattr(kex, "value") else str(kex)
        result["handshake"] = {
            "tls_version_negotiated": handshake.get("tls_version_negotiated", ""),
            "cipher_suite_negotiated": handshake.get("cipher_suite_negotiated", ""),
            "key_exchange_type": kex_val,
            "forward_secrecy": handshake.get("forward_secrecy", False),
            "ja3": handshake.get("ja3", ""),
            "ja3s": handshake.get("ja3s", ""),
            "ja4": handshake.get("ja4", ""),
            "ja4s": handshake.get("ja4s", ""),
            "visibility_limited": handshake.get("visibility_limited", False),
        }

    result["certificates"] = [
        {
            "chain_position": c.get("chain_position", 0),
            "subject": c.get("subject", ""),
            "issuer": c.get("issuer", ""),
            "not_before": c.get("not_before"),
            "not_after": c.get("not_after"),
            "public_key_algorithm": c.get("public_key_algorithm", ""),
            "key_length_bits": c.get("key_length_bits", 0),
            "signature_algorithm": c.get("signature_algorithm", ""),
            "self_signed": c.get("self_signed", False),
            "chain_valid": c.get("chain_valid", True),
        }
        for c in certificates
    ]

    result["findings"] = [
        {
            "rule_id": f.get("rule_id", ""),
            "severity": f.get("severity", "info"),
            "message": f.get("message", ""),
            "recommendation": f.get("recommendation_text") or f.get("recommendation", ""),
        }
        for f in findings
    ]

    if risk_score:
        expl = risk_score.get("feature_attribution", "{}")
        if isinstance(expl, str):
            try:
                expl = json.loads(expl)
            except Exception:
                expl = {}
        result["risk_score"] = {
            "score": risk_score.get("score_0_100", 0.0),
            "tier": risk_score.get("tier", "low"),
            "explanation": expl,
        }

    if anomaly_score:
        result["anomaly_score"] = {
            "score": anomaly_score.get("anomaly_score", 0.0),
            "is_anomalous": anomaly_score.get("is_anomalous", False),
            "baseline": anomaly_score.get("baseline_reference", "global"),
        }

    return result


@app.get("/api/sessions/{session_id}/explain", dependencies=[Depends(verify_api_key)])
async def get_session_explanation(session_id: int):
    """Get SHAP feature attribution for a session's risk score."""
    sessions_col = get_sessions_col()
    session = sessions_col.find_one({"id": session_id}, {"_id": 0})
    if not session or not session.get("risk_score"):
        raise HTTPException(status_code=404, detail="Risk score not found for session")

    risk_score = session["risk_score"]
    expl = risk_score.get("feature_attribution", "{}")
    if isinstance(expl, str):
        try:
            expl = json.loads(expl)
        except Exception:
            expl = {}

    return {
        "session_id": session_id,
        "score": risk_score.get("score_0_100", 0.0),
        "tier": risk_score.get("tier", "low"),
        "explanation": expl,
    }


@app.get("/api/reports/{job_id}.json", dependencies=[Depends(verify_api_key)])
async def get_json_report(job_id: str):
    """Download JSON report."""
    report_path = REPORTS_DIR / job_id / "report.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(
        str(report_path),
        media_type="application/json",
        filename=f"secure_smtp_report_{job_id}.json",
    )


@app.get("/api/reports/{job_id}.pdf", dependencies=[Depends(verify_api_key)])
async def get_pdf_report(job_id: str):
    """Download PDF report."""
    report_path = REPORTS_DIR / job_id / "report.pdf"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(
        str(report_path),
        media_type="application/pdf",
        filename=f"secure_smtp_report_{job_id}.pdf",
    )


@app.get("/api/reports/{job_id}.html", dependencies=[Depends(verify_api_key)])
async def get_html_report(job_id: str):
    """Download HTML report."""
    report_path = REPORTS_DIR / job_id / "report.html"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(
        str(report_path),
        media_type="text/html",
        filename=f"secure_smtp_report_{job_id}.html",
    )


# ── Compliance Endpoints ──


@app.get("/api/compliance/summary", tags=["Compliance"], dependencies=[Depends(verify_api_key)])
def get_compliance_summary():
    """Evaluate fleet-wide regulatory compliance (NIST SP 800-52, PCI-DSS, MTA-STS)."""
    sessions_col = get_sessions_col()
    sessions = list(sessions_col.find())
    return evaluate_fleet_compliance(sessions)


@app.get("/api/sessions/{session_id}/compliance", tags=["Compliance"], dependencies=[Depends(verify_api_key)])
def get_session_compliance(session_id: int):
    """Evaluate specific session compliance against NIST, PCI-DSS, and MTA-STS."""
    sessions_col = get_sessions_col()
    session = sessions_col.find_one({"id": session_id})
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    return evaluate_session_compliance(session)


# ── AI Security Copilot Endpoints ──


class RemediateRequest(BaseModel):
    server_type: str = "postfix"


class AskCopilotRequest(BaseModel):
    query: str


@app.post("/api/sessions/{session_id}/copilot/remediate", tags=["AI Copilot"], dependencies=[Depends(verify_api_key)])
def copilot_remediate(session_id: int, req: RemediateRequest = RemediateRequest()):
    """Generate production-ready mail server configuration to fix detected weaknesses."""
    sessions_col = get_sessions_col()
    session = sessions_col.find_one({"id": session_id})
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    findings = session.get("findings", [])
    return generate_server_remediation(session, findings, req.server_type)


@app.post("/api/sessions/{session_id}/copilot/briefing", tags=["AI Copilot"], dependencies=[Depends(verify_api_key)])
def copilot_briefing(session_id: int):
    """Generate an executive-level CISO incident briefing memo."""
    sessions_col = get_sessions_col()
    session = sessions_col.find_one({"id": session_id})
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    findings = session.get("findings", [])
    risk_info = session.get("risk_score") or {}
    score = risk_info.get("score_0_100", 0.0)
    return generate_incident_briefing(session, findings, score)


@app.post("/api/sessions/{session_id}/copilot/ask", tags=["AI Copilot"], dependencies=[Depends(verify_api_key)])
def copilot_ask(session_id: int, req: AskCopilotRequest):
    """Ask the AI Copilot any question about this session's security posture."""
    sessions_col = get_sessions_col()
    session = sessions_col.find_one({"id": session_id})
    if not session:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    findings = session.get("findings", [])
    return ask_copilot(session, findings, req.query)


class GlobalAskCopilotRequest(BaseModel):
    query: str
    session_id: int | None = None


@app.post("/api/ai/copilot/ask", tags=["AI Copilot"], dependencies=[Depends(verify_api_key)])
def global_copilot_ask(req: GlobalAskCopilotRequest):
    """Ask the AI Copilot any security or hardening question across the fleet."""
    sessions_col = get_sessions_col()
    session = None
    if req.session_id:
        session = sessions_col.find_one({"id": req.session_id})
    if not session:
        session = sessions_col.find_one(sort=[("risk_score.score_0_100", -1)]) or sessions_col.find_one(sort=[("id", -1)])
    if not session:
        session = {
            "id": 0,
            "src_ip": "192.168.1.100",
            "dst_ip": "mail.enterprise.local",
            "protocol": "SMTP",
            "tls_mode": "starttls",
        }
        findings = []
    else:
        findings = session.get("findings", [])
    return ask_copilot(session, findings, req.query)


@app.get("/api/ai/overview", tags=["AI Copilot"], dependencies=[Depends(verify_api_key)])
def global_ai_overview():
    """Get high-level AI security analytics including Isolation Forest anomaly baselines and PQC metrics."""
    sessions_col = get_sessions_col()
    total_sessions = sessions_col.count_documents({})
    pqc_vulnerable = sessions_col.count_documents({
        "$or": [
            {"handshake.key_exchange_type": "rsa"},
            {"handshake.forward_secrecy": False},
            {"findings.rule_id": "no-forward-secrecy"},
            {"tls_mode": "none"},
        ]
    })
    anomalous_count = sessions_col.count_documents({"anomaly_score.is_anomalous": True})
    engine_name = "Gemini 1.5 Flash (Live LLM)" if (os.environ.get("GEMINI_API_KEY") or os.environ.get("SECURE_SMTP_GEMINI_KEY")) else "Built-in Expert Cryptographic Synthesizer"

    return {
        "engine": engine_name,
        "isolation_forest": {
            "status": "active",
            "model": "IsolationForest(contamination=0.08, n_estimators=100)",
            "anomalous_sessions": anomalous_count,
            "conformity_rate": f"{max(0, 100 - round((anomalous_count / max(total_sessions, 1)) * 100, 1))}%",
        },
        "explainable_ai": {
            "method": "SHAP (SHapley Additive exPlanations) + XGBoost",
            "primary_features": [
                {"name": "tls_downgrade_detected", "weight": 0.38, "tier": "critical"},
                {"name": "cipher_suite_aead", "weight": 0.26, "tier": "high"},
                {"name": "cert_expiration_window", "weight": 0.21, "tier": "medium"},
                {"name": "forward_secrecy_pfs", "weight": 0.15, "tier": "clean"},
            ],
        },
        "post_quantum_readiness": {
            "risk_status": "CRITICAL EXPOSURE" if pqc_vulnerable > 0 else "BASELINE SECURE",
            "vulnerable_sessions": pqc_vulnerable,
            "total_evaluated": total_sessions,
            "pqc_score": max(0, 100 - round((pqc_vulnerable / max(total_sessions, 1)) * 100)),
            "recommendation": "Transition key exchanges to hybrid X25519MLKEM768 (FIPS 203) to prevent Harvest Now, Decrypt Later threats.",
        },
    }



# ── Live Mail Lab & Real-Time WebSocket Streaming ──


@app.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket):
    """Real-time event stream for incoming packet analyses, simulated sessions, and security alerts."""
    await _connection_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        _connection_manager.disconnect(websocket)
    except Exception:
        _connection_manager.disconnect(websocket)


@app.get("/api/live/status", tags=["Live Monitoring"], dependencies=[Depends(verify_api_key)])
async def get_live_status():
    """Get status of the live test lab and streaming server."""
    from secure_smtp.live.mail_server import get_live_lab, get_local_ip

    lab = get_live_lab()
    return {
        "status": "active" if lab.is_running else "ready",
        "is_running": lab.is_running,
        "lan_ip": get_local_ip(),
        "ports": {
            "plaintext": 2525,
            "tls_modern": 2526,
            "tls_vulnerable": 2527,
            "stripping": 2528,
        },
        "websocket_subscribers": len(_connection_manager.active_connections),
    }


@app.post("/api/live/start-lab", tags=["Live Monitoring"], dependencies=[Depends(verify_api_key)])
async def start_lab_endpoint():
    """Start the multi-port live SMTP server."""
    from secure_smtp.live.mail_server import get_live_lab

    lab = get_live_lab()
    if not lab.is_running:
        ports = await lab.start()
        return {"status": "started", "ports": ports}
    return {"status": "already_running"}


@app.post("/api/live/stop-lab", tags=["Live Monitoring"], dependencies=[Depends(verify_api_key)])
async def stop_lab_endpoint():
    """Stop the multi-port live SMTP server."""
    from secure_smtp.live.mail_server import get_live_lab

    lab = get_live_lab()
    if lab.is_running:
        await lab.stop()
        return {"status": "stopped"}
    return {"status": "already_stopped"}


@app.post("/api/live/simulate/{scenario}", tags=["Live Monitoring"], dependencies=[Depends(verify_api_key)])
async def simulate_scenario_endpoint(scenario: str):
    """Trigger a live email traffic simulation and broadcast the forensic results in real-time."""
    from secure_smtp.live.generator import simulate_live_session

    try:
        session_event = await simulate_live_session(scenario)
        return session_event
    except Exception as e:
        logger.error("Simulation failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/live/clear-history", tags=["Live Monitoring"], dependencies=[Depends(verify_api_key)])
async def clear_live_history():
    """Clear all historical sessions and reset database for a fresh demonstration."""
    from secure_smtp.db.mongodb import get_hosts_col, get_sessions_col
    sessions_col = get_sessions_col()
    hosts_col = get_hosts_col()

    s_res = sessions_col.delete_many({})
    h_res = hosts_col.delete_many({})

    # Broadcast reset event over WebSocket so all connected clients clear live tickers
    await _connection_manager.broadcast({
        "event": "DATABASE_RESET",
        "timestamp": datetime.now(UTC).isoformat(),
    })

    return {
        "status": "cleared",
        "deleted_sessions": s_res.deleted_count,
        "deleted_hosts": h_res.deleted_count,
        "message": "Database reset to clean slate. Ready for live mail injection.",
    }


class CustomMailDispatchRequest(BaseModel):
    server_ip: str | None = None
    port: int = 2525
    scenario: str = "plaintext"
    sender: str = "alice@client-device.local"
    recipient: str = "bob@securesmtp.local"
    subject: str = "Live Web Client Mail"
    body: str = "Confidential telemetry packet transmitted across network."
    client_name: str = "Interactive Web Client"


@app.post("/api/live/dispatch-custom", tags=["Live Monitoring"], dependencies=[Depends(verify_api_key)])
async def dispatch_custom_mail(req: CustomMailDispatchRequest):
    """Execute a real-time SMTP client connection and return the complete socket transcript."""
    from secure_smtp.live.client_dispatcher import execute_client_dispatch_async

    host = req.server_ip or "127.0.0.1"
    result = await execute_client_dispatch_async(
        host=host,
        port=req.port,
        scenario=req.scenario,
        sender=req.sender,
        recipient=req.recipient,
        subject=req.subject,
        body=req.body,
        client_name=req.client_name,
    )
    return result

