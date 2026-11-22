"""
PCAP Analysis & Reporting Pipeline.

Orchestrates the complete inspection pipeline:
PCAP -> TCP streams -> Protocol ID -> TLS handshake ->
Cert parsing -> Rule engine -> AI scoring -> MongoDB storage -> Report generation.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from pymongo.errors import DuplicateKeyError

from secure_smtp.config import get_settings
from secure_smtp.db.models import (
    Certificate,
    RiskScore,
    Session,
    TLSHandshake,
)
from secure_smtp.db.mongodb import (
    get_hosts_col,
    get_jobs_col,
    get_next_sequence,
    get_sessions_col,
)

logger = logging.getLogger(__name__)


def build_report_data(hosts: list[dict], sessions: list[dict]) -> dict:
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
        report["hosts"].append(
            {
                "id": host.get("id"),
                "ip_or_hostname": host.get("ip_or_hostname"),
                "session_count": host.get("session_count", 0),
                "aggregate_risk_score": host.get("aggregate_risk_score", 0.0),
            }
        )

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
                    "chain_valid": c.get("chain_valid"),
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
            }
            if risk_score
            else None,
            "anomaly_score": {
                "score": anomaly_score.get("anomaly_score", 0.0) if anomaly_score else 0.0,
                "is_anomalous": anomaly_score.get("is_anomalous", False)
                if anomaly_score
                else False,
                "baseline": anomaly_score.get("baseline_reference", "global")
                if anomaly_score
                else "global",
            }
            if anomaly_score
            else None,
        }
        report["sessions"].append(session_data)

    return report


def generate_job_reports(job_id: str) -> None:
    """Generate JSON, HTML, and PDF reports for a completed analysis from MongoDB."""
    from secure_smtp.reporting.html_export import generate_html_report
    from secure_smtp.reporting.json_export import generate_json_report
    from secure_smtp.reporting.pdf_export import generate_pdf_report

    settings = get_settings()
    job_dir = settings.reports_dir / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    hosts_col = get_hosts_col()
    sessions_col = get_sessions_col()

    job = get_jobs_col().find_one({"job_id": job_id})
    if not job or not job.get("org_id"):
        raise ValueError("Assessment ownership is missing")
    sessions = list(sessions_col.find({"org_id": job["org_id"], "job_id": job_id}, {"_id": 0}))
    # Report host counts and scores describe this assessment, never the cumulative fleet.
    from secure_smtp.ai.risk_model import compute_host_rollup

    hosts = []
    for host_id in {s["host_id"] for s in sessions}:
        records = [s for s in sessions if s["host_id"] == host_id]
        host = hosts_col.find_one({"id": host_id, "org_id": job["org_id"]}, {"_id": 0})
        if not host:
            raise ValueError("Assessment host is missing")
        host["session_count"] = len(records)
        host["aggregate_risk_score"] = compute_host_rollup(
            [RiskScore(**s["risk_score"]) for s in records if s.get("risk_score")]
        )
        hosts.append(host)

    report_data = build_report_data(hosts, sessions)

    # JSON report
    json_path = job_dir / "report.json"
    generate_json_report(report_data, str(json_path))

    # HTML report
    html_path = job_dir / "report.html"
    generate_html_report(report_data, str(html_path))

    # PDF report
    pdf_path = job_dir / "report.pdf"
    generate_pdf_report(str(html_path), str(pdf_path), report_data=report_data)


def run_pcap_analysis(job_id: str, pcap_path: str) -> None:
    """
    Background task: run the full analysis pipeline on a PCAP file and persist to MongoDB.

    Pipeline: PCAP -> TCP streams -> Protocol ID -> TLS handshake ->
    Cert parsing -> Rule engine -> AI scoring -> MongoDB storage -> Report generation.
    """
    from secure_smtp.ai.anomaly_model import AnomalyDetector
    from secure_smtp.ai.explain import enrich_risk_score_with_explanation
    from secure_smtp.ai.features import build_feature_vector
    from secure_smtp.ai.risk_model import RiskModel
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

    job = jobs_col.find_one({"job_id": job_id})
    if not job or not job.get("org_id"):
        raise ValueError("Assessment ownership is missing")
    org_id = job["org_id"]
    from uuid import uuid4

    run_id = str(uuid4())
    lease = {"job_id": job_id, "run_id": run_id, "status": "running"}
    claimed = jobs_col.update_one(
        {"job_id": job_id, "status": "queued"}, {"$set": {"status": "running", "run_id": run_id}}
    )
    if not claimed.modified_count:
        raise RuntimeError("Assessment is no longer queued")

    try:
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
            if not jobs_col.find_one(lease):
                raise RuntimeError("Assessment lease expired")
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
            host_doc = hosts_col.find_one(
                {
                    "$or": [
                        {"ip_or_hostname": reassembled.server_ip, "org_id": org_id},
                        {"ip_or_hostname": reassembled.server_ip},
                    ]
                }
            )
            if not host_doc:
                host_id = get_next_sequence("host_id")
                host_data = {
                    "id": host_id,
                    "org_id": org_id,
                    "ip_or_hostname": reassembled.server_ip,
                    "published": False,
                    "session_count": 0,
                    "aggregate_risk_score": 0.0,
                }
                try:
                    hosts_col.insert_one(host_data)
                except DuplicateKeyError:
                    host_doc = hosts_col.find_one({"ip_or_hostname": reassembled.server_ip})
                    host_id = host_doc["id"] if host_doc else host_id
            else:
                host_id = host_doc["id"]
                if not host_doc.get("org_id"):
                    hosts_col.update_one({"_id": host_doc["_id"]}, {"$set": {"org_id": org_id}})

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
                fingerprints = compute_fingerprints(parsed_hs.client_hello, parsed_hs.server_hello)

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
                    extensions=json.dumps(
                        {
                            str(k): v.hex()
                            for k, v in (
                                parsed_hs.client_hello.extensions.items()
                                if parsed_hs.client_hello
                                else {}
                            )
                        }
                    ),
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
            findings = rule_engine.evaluate_session(session, handshake_model, certificates_models)
            for finding in findings:
                finding.session_id = session.id

            # Stage 5: Feature vector + risk scoring
            fv = build_feature_vector(session, handshake_model, certificates_models, findings)
            risk_score = risk_model.score_session(fv, findings)
            risk_score.session_id = session.id
            risk_score = enrich_risk_score_with_explanation(risk_score, findings, fv)

            # Assemble complete session document for MongoDB
            session.handshake = handshake_model
            session.certificates = certificates_models
            session.findings = findings
            session.risk_score = risk_score

            session_dict = session.model_dump()
            session_dict.update(
                published=False,
                run_id=run_id,
                org_id=org_id,
                owner_id=job.get("owner_id", "system"),
                job_id=job_id,
                source_kind=job.get("source_kind", "manual_capture"),
            )
            sessions_col.insert_one(session_dict)

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

        # Generate reports
        generate_job_reports(job_id)

        # Mark job as done
        completed = jobs_col.update_one(
            lease,
            {
                "$set": {
                    "status": "done",
                    "completed_at": datetime.now(UTC),
                }
            },
        )

        if not completed.modified_count:
            raise RuntimeError("Assessment lease expired before publication")
        sessions_col.update_many(
            {"job_id": job_id, "org_id": org_id}, {"$set": {"published": True}}
        )
        from secure_smtp.monitoring.service import refresh_hosts

        refresh_hosts(org_id)
        from secure_smtp.operations.integrations import run_integrations

        run_integrations(org_id, job_id)
        logger.info("Job %s: Analysis complete", job_id)

    except Exception as e:
        logger.error("Job %s failed (%s)", job_id, type(e).__name__)
        jobs_col.update_one(
            lease,
            {
                "$set": {
                    "status": "failed",
                    "error_message": "Capture analysis failed. The file may be corrupt, unsupported, or exceed processing limits.",
                    "completed_at": datetime.now(UTC),
                }
            },
        )
