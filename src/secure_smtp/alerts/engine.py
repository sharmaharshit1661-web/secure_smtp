"""
Real-Time Alerting & Webhooks Notification Engine — Secure SMTP.

Dispatches cryptographic risk and rule violation alerts to Slack, Microsoft Teams,
Discord, or generic enterprise SIEM/SOAR webhooks with HMAC-SHA256 signatures.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional

import httpx

from secure_smtp.config import get_settings

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class AlertEngine:
    """
    Evaluates analysis findings and dispatches structured security alerts
    to configured webhook endpoints.
    """

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        secret: Optional[str] = None,
        min_severity: Optional[str] = None,
        risk_threshold: Optional[float] = None,
        enabled: Optional[bool] = None,
    ):
        settings = get_settings()
        self.webhook_url = webhook_url or settings.alert_webhook_url
        self.secret = secret or settings.alert_webhook_secret
        self.min_severity = (min_severity or settings.alert_min_severity).upper()
        self.risk_threshold = settings.alert_risk_threshold if risk_threshold is None else risk_threshold
        self.enabled = enabled if enabled is not None else (settings.alerts_enabled and bool(self.webhook_url))

    def should_alert(self, findings: List[Dict[str, Any]], risk_score: float) -> bool:
        """Determine whether the findings or risk score meet the alert threshold."""
        if not self.enabled or not self.webhook_url:
            return False

        if risk_score >= self.risk_threshold:
            return True

        min_level = SEVERITY_ORDER.get(self.min_severity, 3)
        for f in findings:
            f_sev = f.get("severity", "LOW").upper()
            if SEVERITY_ORDER.get(f_sev, 0) >= min_level:
                return True

        return False

    def build_payload(
        self,
        session_id: int | str,
        client_ip: str,
        server_ip: str,
        protocol: str,
        risk_score: float,
        findings: List[Dict[str, Any]],
        pcap_source: str = "",
    ) -> Dict[str, Any]:
        """Construct standard JSON webhook payload."""
        timestamp = datetime.now(UTC).isoformat()
        critical_findings = [
            f.get("title") or f.get("rule_id", "Finding")
            for f in findings
            if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
        ]

        payload = {
            "event": "cryptographic_posture_alert",
            "timestamp": timestamp,
            "session_id": session_id,
            "traffic": {
                "client_ip": client_ip,
                "server_ip": server_ip,
                "protocol": protocol.upper(),
                "pcap_source": pcap_source,
            },
            "security": {
                "risk_score": risk_score,
                "risk_tier": "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 60 else "MEDIUM",
                "finding_count": len(findings),
                "critical_findings": critical_findings,
            },
            "details": findings[:10],
        }

        # Format specifically for Slack if webhook URL is Slack
        if self.webhook_url and "slack.com" in self.webhook_url.lower():
            slack_text = (
                f"🚨 *Secure SMTP Security Alert*: High Risk {protocol.upper()} Session Detected\n"
                f"• *Host/IP*: `{server_ip}` (Client: `{client_ip}`)\n"
                f"• *Risk Score*: `{risk_score:.1f}/100` ({payload['security']['risk_tier']})\n"
                f"• *Violations*: {', '.join(critical_findings) if critical_findings else 'High Risk Attributed'}"
            )
            return {"text": slack_text, "attachments": [{"color": "#e11d48", "fields": [
                {"title": "Protocol", "value": protocol.upper(), "short": True},
                {"title": "Risk Score", "value": f"{risk_score:.1f}", "short": True},
                {"title": "Violations", "value": f"{len(findings)} rules fired", "short": False},
            ]}]}

        return payload

    def sign_payload(self, body_bytes: bytes) -> str:
        """Compute HMAC-SHA256 signature using the shared secret."""
        if not self.secret:
            return ""
        return "sha256=" + hmac.new(
            self.secret.encode("utf-8"), body_bytes, hashlib.sha256
        ).hexdigest()

    def send(
        self,
        session_id: int | str,
        client_ip: str,
        server_ip: str,
        protocol: str,
        risk_score: float,
        findings: List[Dict[str, Any]],
        pcap_source: str = "",
    ) -> bool:
        """Synchronously or background-dispatch alert with timeout."""
        if not self.should_alert(findings, risk_score):
            return False

        payload = self.build_payload(
            session_id, client_ip, server_ip, protocol, risk_score, findings, pcap_source
        )
        body_bytes = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "SecureSMTP-AlertBot/1.0"}

        sig = self.sign_payload(body_bytes)
        if sig:
            headers["X-SecureSMTP-Signature"] = sig

        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.post(self.webhook_url, content=body_bytes, headers=headers)
                if res.is_success:
                    logger.info("Security alert dispatched (HTTP %d)", res.status_code)
                    return True
                else:
                    logger.warning("Webhook dispatch failed with HTTP %d: %s", res.status_code, res.text[:200])
                    return False
        except Exception as e:
            logger.error("Webhook delivery failed (%s)", type(e).__name__)
            return False


def dispatch_alert(
    session_id: int | str,
    client_ip: str,
    server_ip: str,
    protocol: str,
    risk_score: float,
    findings: List[Dict[str, Any]],
    pcap_source: str = "",
) -> bool:
    """Convenience helper to evaluate and dispatch alert using global settings."""
    engine = AlertEngine()
    return engine.send(
        session_id=session_id,
        client_ip=client_ip,
        server_ip=server_ip,
        protocol=protocol,
        risk_score=risk_score,
        findings=findings,
        pcap_source=pcap_source,
    )
